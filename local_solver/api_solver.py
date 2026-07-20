import os
import sys
import time
import uuid
import random
import logging
import asyncio
from typing import Optional, List, Dict, Any
import argparse
import atexit
from urllib.parse import urlsplit, urlunsplit
from quart import Quart, request, jsonify

# Windows console UTF-8 (avoid emoji/GBK crash)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
try:
    from camoufox.async_api import AsyncCamoufox
except Exception:
    AsyncCamoufox = None

try:
    from patchright.async_api import async_playwright
except Exception:
    async_playwright = None
from db_results import init_db, save_result, load_result, cleanup_old_results
from browser_configs import BrowserConfig as browser_config
from turnstile_engine import solve_turnstile_token, load_proxy_list, parse_proxy, init_worker_pool, shutdown_worker_pool
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box


COLORS = {
    "MAGENTA": "\033[35m",
    "BLUE": "\033[34m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "RED": "\033[31m",
    "RESET": "\033[0m",
}


def mask_proxy(proxy: Optional[str]) -> str:
    """Mask proxy credentials for logs."""
    if not proxy:
        return ""
    try:
        u = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        host = u.hostname or ""
        netloc = host
        if u.port:
            netloc = f"{netloc}:{u.port}"
        if u.username:
            netloc = f"***:***@{netloc}"
        return urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment))
    except Exception:
        return "***"


class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime("%H:%M:%S")
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message("DEBUG", "MAGENTA", message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message("INFO", "BLUE", message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message("SUCCESS", "GREEN", message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(
            self.format_message("WARNING", "YELLOW", message), *args, **kwargs
        )

    def error(self, message, *args, **kwargs):
        super().error(self.format_message("ERROR", "RED", message), *args, **kwargs)


logging.setLoggerClass(CustomLogger)
logger: CustomLogger = logging.getLogger("TurnstileAPIServer")  # type: ignore
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


class TurnstileAPIServer:
    def __init__(
        self,
        headless: bool,
        useragent: Optional[str],
        debug: bool,
        browser_type: str,
        thread: int,
        proxy_support: bool,
        use_random_config: bool = False,
        browser_name: Optional[str] = None,
        browser_version: Optional[str] = None,
    ):
        self.app = Quart(__name__)
        self.debug = debug
        self.browser_type = browser_type
        self.headless = headless
        self.thread_count = thread
        self.proxy_support = proxy_support
        self.browser_pool = asyncio.Queue()
        self.solve_semaphore: Optional[asyncio.Semaphore] = None
        self.active_tasks: Dict[str, asyncio.Task] = {}
        self.cancelled_tasks: set[str] = set()
        self.use_random_config = use_random_config
        self.browser_name = browser_name
        self.browser_version = browser_version
        self.console = Console()

        # Initialize useragent and sec_ch_ua attributes
        self.useragent = useragent
        self.sec_ch_ua = None

        if self.browser_type in ["chromium", "chrome", "msedge"]:
            if browser_name and browser_version:
                config = browser_config.get_browser_config(
                    browser_name, browser_version
                )
                if config:
                    useragent, sec_ch_ua = config
                    self.useragent = useragent
                    self.sec_ch_ua = sec_ch_ua
            elif useragent:
                self.useragent = useragent
            else:
                browser, version, useragent, sec_ch_ua = (
                    browser_config.get_random_browser_config(self.browser_type)
                )
                self.browser_name = browser
                self.browser_version = version
                self.useragent = useragent
                self.sec_ch_ua = sec_ch_ua

        self.browser_args = []
        if self.useragent:
            self.browser_args.append(f"--user-agent={self.useragent}")

        self._setup_routes()

    def _load_proxy_list(self) -> List[str]:
        """Load proxies from proxies.txt and HTTP(S)_PROXY env, strip BOM."""
        proxies: List[str] = []
        proxy_file = os.path.join(os.getcwd(), "proxies.txt")
        if os.path.exists(proxy_file):
            try:
                with open(proxy_file, "r", encoding="utf-8-sig") as f:
                    for line in f:
                        line = line.strip().lstrip("\ufeff")
                        if not line or line.startswith("#"):
                            continue
                        if "://" not in line:
                            line = "http://" + line
                        proxies.append(line)
            except Exception as e:
                logger.warning(f"Failed reading proxies.txt: {e}")

        for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            val = (os.getenv(key) or "").strip().lstrip("\ufeff")
            if val:
                if "://" not in val:
                    val = "http://" + val
                if val not in proxies:
                    proxies.append(val)

        return proxies

    def _parse_proxy(self, proxy: str) -> Optional[Dict[str, Any]]:
        """Parse proxy URL into Playwright proxy dict."""
        if not proxy:
            return None
        proxy = proxy.strip().lstrip("\ufeff")
        if "://" not in proxy:
            proxy = "http://" + proxy
        try:
            from urllib.parse import urlparse
            u = urlparse(proxy)
            if not u.hostname or not u.port:
                # fallback: treat whole string as server
                return {"server": proxy}
            server = f"{u.scheme}://{u.hostname}:{u.port}"
            conf: Dict[str, Any] = {"server": server}
            if u.username:
                conf["username"] = u.username
            if u.password:
                conf["password"] = u.password
            return conf
        except Exception:
            return {"server": proxy}

    def display_welcome(self):

        """Displays welcome screen with logo."""
        self.console.clear()

        combined_text = Text()
        combined_text.append("\n📢 Channel: ", style="bold white")
        combined_text.append("https://t.me/D3_vin", style="cyan")
        combined_text.append("\n💬 Chat: ", style="bold white")
        combined_text.append("https://t.me/D3vin_chat", style="cyan")
        combined_text.append("\n📁 GitHub: ", style="bold white")
        combined_text.append("https://github.com/D3-vin", style="cyan")
        combined_text.append("\n📁 Version: ", style="bold white")
        combined_text.append("1.2a", style="green")
        combined_text.append("\n")

        info_panel = Panel(
            Align.left(combined_text),
            title="[bold blue]Turnstile Solver[/bold blue]",
            subtitle="[bold magenta]Dev by D3vin[/bold magenta]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=50,
        )

        self.console.print(info_panel)
        self.console.print()

    def _setup_routes(self) -> None:
        """Set up the application routes."""
        self.app.before_serving(self._startup)
        self.app.after_serving(self._shutdown)
        self.app.route("/turnstile", methods=["GET"])(self.process_turnstile)
        self.app.route("/result", methods=["GET"])(self.get_result)
        self.app.route("/cancel", methods=["GET", "POST"])(self.cancel_task)
        self.app.route("/cancel_all", methods=["GET", "POST"])(self.cancel_all_tasks)
        self.app.route("/")(self.index)

    async def _startup(self) -> None:
        """Initialize local Chrome workers used by the free solver."""
        self.display_welcome()
        logger.info("Starting solver initialization")
        try:
            await init_db()
            self.solve_semaphore = asyncio.Semaphore(max(1, int(self.thread_count or 1)))

            # Legacy patchright/camoufox pool is unused by /turnstile now.
            # Keep it opt-in so we do not leak extra Chrome processes by default.
            if os.getenv("ENABLE_LEGACY_BROWSER_POOL", "").strip().lower() in {"1", "true", "yes", "on"}:
                await self._initialize_browser()
            else:
                logger.info("Skipping legacy browser pool (using Chrome CDP workers only)")

            # Isolated Chrome workers for local free solver (one process/page per task)
            mode = (os.getenv("SOLVER_BROWSER_MODE") or ("headless" if self.headless else "headed")).strip()
            try:
                await init_worker_pool(size=self.thread_count, mode=mode)
                logger.info(
                    f"Chrome worker pool initialized: workers={self.thread_count} mode={mode}"
                )
            except Exception as e:
                logger.error(f"Chrome worker pool init failed: {e}")

            asyncio.create_task(self._periodic_cleanup())

        except Exception as e:
            logger.error(f"Failed to initialize solver: {str(e)}")
            raise

    async def _shutdown(self) -> None:
        """Release all browser resources on server stop."""
        try:
            for task_id, task in list(self.active_tasks.items()):
                self.cancelled_tasks.add(task_id)
                if not task.done():
                    task.cancel()
            if self.active_tasks:
                await asyncio.gather(*list(self.active_tasks.values()), return_exceptions=True)
        except Exception as e:
            logger.error(f"Active solver task cancellation error: {e}")
        try:
            logger.info("Shutting down legacy browser pool...")
            await self._shutdown_legacy_browser_pool()
        except Exception as e:
            logger.error(f"Legacy browser pool shutdown error: {e}")
        try:
            logger.info("Shutting down Chrome worker pool...")
            shutdown_worker_pool()
        except Exception as e:
            logger.error(f"Worker pool shutdown error: {e}")

    async def _shutdown_legacy_browser_pool(self) -> None:
        """Close unused patchright/camoufox browsers if they were launched."""
        closed = 0
        # Prefer tracked list if present
        legacy = list(getattr(self, "_legacy_browsers", []) or [])
        self._legacy_browsers = []
        for browser in legacy:
            try:
                await browser.close()
                closed += 1
            except Exception as e:
                logger.debug(f"legacy browser close failed: {e}")

        try:
            while not self.browser_pool.empty():
                try:
                    item = self.browser_pool.get_nowait()
                except Exception:
                    break
                browser = None
                if isinstance(item, tuple) and len(item) >= 2:
                    browser = item[1]
                elif item is not None:
                    browser = item
                if browser is not None and browser not in legacy:
                    try:
                        await browser.close()
                        closed += 1
                    except Exception as e:
                        logger.debug(f"legacy browser close failed: {e}")
        except Exception as e:
            logger.debug(f"legacy pool drain failed: {e}")

        playwright = getattr(self, "_playwright", None)
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception as e:
                logger.debug(f"playwright stop failed: {e}")
            self._playwright = None

        camoufox = getattr(self, "_camoufox", None)
        if camoufox is not None:
            try:
                stop = getattr(camoufox, "stop", None) or getattr(camoufox, "close", None)
                if callable(stop):
                    result = stop()
                    if hasattr(result, "__await__"):
                        await result
            except Exception as e:
                logger.debug(f"camoufox stop failed: {e}")
            self._camoufox = None

        if closed:
            logger.info(f"Closed {closed} legacy browser instance(s)")

    async def _initialize_browser(self) -> None:
        """Initialize the browser and create the page pool."""
        playwright = None
        camoufox = None
        self._playwright = None
        self._camoufox = None
        self._legacy_browsers = []

        if self.browser_type in ["chromium", "chrome", "msedge"]:
            if async_playwright is None:
                raise RuntimeError("patchright is required for legacy browser pool")
            playwright = await async_playwright().start()
            self._playwright = playwright
        elif self.browser_type == "camoufox":
            if AsyncCamoufox is None:
                raise RuntimeError("camoufox is required for browser_type=camoufox")
            camoufox = AsyncCamoufox(headless=self.headless)
            self._camoufox = camoufox

        browser_configs = []
        for _ in range(self.thread_count):
            if self.browser_type in ["chromium", "chrome", "msedge"]:
                if self.use_random_config:
                    browser, version, useragent, sec_ch_ua = (
                        browser_config.get_random_browser_config(self.browser_type)
                    )
                elif self.browser_name and self.browser_version:
                    config = browser_config.get_browser_config(
                        self.browser_name, self.browser_version
                    )
                    if config:
                        useragent, sec_ch_ua = config
                        browser = self.browser_name
                        version = self.browser_version
                    else:
                        browser, version, useragent, sec_ch_ua = (
                            browser_config.get_random_browser_config(self.browser_type)
                        )
                else:
                    browser = getattr(self, "browser_name", "custom")
                    version = getattr(self, "browser_version", "custom")
                    useragent = self.useragent
                    sec_ch_ua = getattr(self, "sec_ch_ua", "")
            else:
                # Для camoufox и других браузеров используем значения по умолчанию
                browser = self.browser_type
                version = "custom"
                useragent = self.useragent
                sec_ch_ua = getattr(self, "sec_ch_ua", "")

            browser_configs.append(
                {
                    "browser_name": browser,
                    "browser_version": version,
                    "useragent": useragent,
                    "sec_ch_ua": sec_ch_ua,
                }
            )

        for i in range(self.thread_count):
            config = browser_configs[i]

            browser_args = ["--window-position=0,0", "--force-device-scale-factor=1"]
            if config["useragent"]:
                browser_args.append(f"--user-agent={config['useragent']}")

            browser = None
            if self.browser_type in ["chromium", "chrome", "msedge"] and playwright:
                launch_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-infobars",
                    "--window-position=0,0",
                    "--force-device-scale-factor=1",
                ]
                if config["useragent"]:
                    launch_args.append(f"--user-agent={config['useragent']}")
                launch_kwargs = {
                    "headless": self.headless,
                    "args": launch_args,
                }
                # Only use channel for real chrome/msedge installs
                if self.browser_type in ("chrome", "msedge"):
                    launch_kwargs["channel"] = self.browser_type
                browser = await playwright.chromium.launch(**launch_kwargs)
            elif self.browser_type == "camoufox" and camoufox:
                browser = await camoufox.start()

            if browser:
                self._legacy_browsers.append(browser)
                await self.browser_pool.put((i + 1, browser, config))

            if self.debug:
                logger.info(
                    f"Browser {i + 1} initialized successfully with {config['browser_name']} {config['browser_version']}"
                )

        logger.info(
            f"Browser pool initialized with {self.browser_pool.qsize()} browsers"
        )

        if self.use_random_config:
            logger.info(f"Each browser in pool received random configuration")
        elif self.browser_name and self.browser_version:
            logger.info(
                f"All browsers using configuration: {self.browser_name} {self.browser_version}"
            )
        else:
            logger.info("Using custom configuration")

        if self.debug:
            for i, config in enumerate(browser_configs):
                logger.debug(
                    f"Browser {i + 1} config: {config['browser_name']} {config['browser_version']}"
                )
                logger.debug(f"Browser {i + 1} User-Agent: {config['useragent']}")
                logger.debug(f"Browser {i + 1} Sec-CH-UA: {config['sec_ch_ua']}")

    async def _periodic_cleanup(self):
        """Periodic cleanup of old results every hour"""
        while True:
            try:
                await asyncio.sleep(3600)
                deleted_count = await cleanup_old_results(days_old=7)
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old results")
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")

    async def _antishadow_inject(self, page):
        await page.add_init_script("""
          (function() {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
              const shadow = originalAttachShadow.call(this, init);
              if (init.mode === 'closed') {
                window.__lastClosedShadowRoot = shadow;
              }
              return shadow;
            };
          })();
        """)

    async def _optimized_route_handler(self, route):
        """Resource filter: keep CF/xAI scripts, drop heavy media."""
        url = route.request.url
        resource_type = route.request.resource_type

        # Never block these critical domains
        allowed_domains = [
            "challenges.cloudflare.com",
            "static.cloudflareinsights.com",
            "cloudflare.com",
            "accounts.x.ai",
            "x.ai",
            "grok.com",
        ]
        if any(domain in url for domain in allowed_domains):
            await route.continue_()
            return

        # Block only heavy non-essential types
        blocked_types = {"image", "media", "font", "stylesheet", "manifest", "other"}
        if resource_type in blocked_types:
            await route.abort()
            return

        await route.continue_()

    async def _block_rendering(self, page):
        """Блокировка рендеринга для экономии ресурсов"""
        await page.route("**/*", self._optimized_route_handler)

    async def _unblock_rendering(self, page):
        """Разблокировка рендеринга"""
        await page.unroute("**/*", self._optimized_route_handler)

    async def _find_turnstile_elements(self, page, index: int):
        """Умная проверка всех возможных Turnstile элементов"""
        selectors = [
            ".cf-turnstile",
            "[data-sitekey]",
            'iframe[src*="turnstile"]',
            'iframe[title*="widget"]',
            'div[id*="turnstile"]',
            'div[class*="turnstile"]',
        ]

        elements = []
        for selector in selectors:
            try:
                # Безопасная проверка count()
                try:
                    count = await page.locator(selector).count()
                except Exception:
                    # Если count() дает ошибку, пропускаем этот селектор
                    continue

                if count > 0:
                    elements.append((selector, count))
                    if self.debug:
                        logger.debug(
                            f"Browser {index}: Found {count} elements with selector '{selector}'"
                        )
            except Exception as e:
                if self.debug:
                    logger.debug(
                        f"Browser {index}: Selector '{selector}' failed: {str(e)}"
                    )
                continue

        return elements

    async def _find_and_click_checkbox(self, page, index: int):
        """Найти и кликнуть по чекбоксу Turnstile CAPTCHA внутри iframe"""
        try:
            # Пробуем разные селекторы iframe с защитой от ошибок
            iframe_selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                'iframe[title*="widget"]',
            ]

            iframe_locator = None
            for selector in iframe_selectors:
                try:
                    test_locator = page.locator(selector).first
                    # Безопасная проверка count для iframe
                    try:
                        iframe_count = await test_locator.count()
                    except Exception:
                        iframe_count = 0

                    if iframe_count > 0:
                        iframe_locator = test_locator
                        if self.debug:
                            logger.debug(
                                f"Browser {index}: Found Turnstile iframe with selector: {selector}"
                            )
                        break
                except Exception as e:
                    if self.debug:
                        logger.debug(
                            f"Browser {index}: Iframe selector '{selector}' failed: {str(e)}"
                        )
                    continue

            if iframe_locator:
                try:
                    # Получаем frame из iframe
                    iframe_element = await iframe_locator.element_handle()
                    frame = await iframe_element.content_frame()

                    if frame:
                        # Ищем чекбокс внутри iframe
                        checkbox_selectors = [
                            'input[type="checkbox"]',
                            '.cb-lb input[type="checkbox"]',
                            'label input[type="checkbox"]',
                        ]

                        for selector in checkbox_selectors:
                            try:
                                # Полностью избегаем locator.count() в iframe - используем альтернативный подход
                                try:
                                    # Пробуем кликнуть напрямую без count проверки
                                    checkbox = frame.locator(selector).first
                                    await checkbox.click(timeout=2000)
                                    if self.debug:
                                        logger.debug(
                                            f"Browser {index}: Successfully clicked checkbox in iframe with selector '{selector}'"
                                        )
                                    return True
                                except Exception as click_e:
                                    # Если прямой клик не сработал, записываем в debug но не падаем
                                    if self.debug:
                                        logger.debug(
                                            f"Browser {index}: Direct checkbox click failed for '{selector}': {str(click_e)}"
                                        )
                                    continue
                            except Exception as e:
                                if self.debug:
                                    logger.debug(
                                        f"Browser {index}: Iframe checkbox selector '{selector}' failed: {str(e)}"
                                    )
                                continue

                        # Если нашли iframe, но не смогли кликнуть чекбокс, пробуем клик по iframe
                        try:
                            if self.debug:
                                logger.debug(
                                    f"Browser {index}: Trying to click iframe directly as fallback"
                                )
                            await iframe_locator.click(timeout=1000)
                            return True
                        except Exception as e:
                            if self.debug:
                                logger.debug(
                                    f"Browser {index}: Iframe direct click failed: {str(e)}"
                                )

                except Exception as e:
                    if self.debug:
                        logger.debug(
                            f"Browser {index}: Failed to access iframe content: {str(e)}"
                        )

        except Exception as e:
            if self.debug:
                logger.debug(f"Browser {index}: General iframe search failed: {str(e)}")

        return False

    async def _try_click_strategies(self, page, index: int):
        strategies = [
            ("checkbox_click", lambda: self._find_and_click_checkbox(page, index)),
            ("direct_widget", lambda: self._safe_click(page, ".cf-turnstile", index)),
            (
                "iframe_click",
                lambda: self._safe_click(page, 'iframe[src*="turnstile"]', index),
            ),
            (
                "js_click",
                lambda: page.evaluate(
                    "document.querySelector('.cf-turnstile')?.click()"
                ),
            ),
            ("sitekey_attr", lambda: self._safe_click(page, "[data-sitekey]", index)),
            (
                "any_turnstile",
                lambda: self._safe_click(page, '*[class*="turnstile"]', index),
            ),
            (
                "xpath_click",
                lambda: self._safe_click(page, "//div[@class='cf-turnstile']", index),
            ),
        ]

        for strategy_name, strategy_func in strategies:
            try:
                result = await strategy_func()
                if (
                    result is True or result is None
                ):  # None означает успех для большинства стратегий
                    if self.debug:
                        logger.debug(
                            f"Browser {index}: Click strategy '{strategy_name}' succeeded"
                        )
                    return True
            except Exception as e:
                if self.debug:
                    logger.debug(
                        f"Browser {index}: Click strategy '{strategy_name}' failed: {str(e)}"
                    )
                continue

        return False

    async def _safe_click(self, page, selector: str, index: int):
        """Полностью безопасный клик с максимальной защитой от ошибок"""
        try:
            # Пробуем кликнуть напрямую без count() проверки
            locator = page.locator(selector).first
            await locator.click(timeout=1000)
            return True
        except Exception as e:
            # Логируем ошибку только в debug режиме
            if self.debug and "Can't query n-th element" not in str(e):
                logger.debug(
                    f"Browser {index}: Safe click failed for '{selector}': {str(e)}"
                )
            return False

    async def _inject_captcha_directly(
        self, page, websiteKey: str, action: str = "", cdata: str = "", index: int = 0
    ):
        """Inject CAPTCHA directly into the target website"""
        script = f"""
        // Remove any existing turnstile widgets first
        document.querySelectorAll('.cf-turnstile').forEach(el => el.remove());
        document.querySelectorAll('[data-sitekey]').forEach(el => el.remove());
        
        // Create turnstile widget directly on the page
        const captchaDiv = document.createElement('div');
        captchaDiv.className = 'cf-turnstile';
        captchaDiv.setAttribute('data-sitekey', '{websiteKey}');
        captchaDiv.setAttribute('data-callback', 'onTurnstileCallback');
        {f'captchaDiv.setAttribute("data-action", "{action}");' if action else ""}
        {f'captchaDiv.setAttribute("data-cdata", "{cdata}");' if cdata else ""}
        captchaDiv.style.position = 'fixed';
        captchaDiv.style.top = '20px';
        captchaDiv.style.left = '20px';
        captchaDiv.style.zIndex = '9999';
        captchaDiv.style.backgroundColor = 'white';
        captchaDiv.style.padding = '15px';
        captchaDiv.style.border = '2px solid #0f79af';
        captchaDiv.style.borderRadius = '8px';
        captchaDiv.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)';
        
        // Add to body immediately
        document.body.appendChild(captchaDiv);
        
        // Load Turnstile script and render widget
        const loadTurnstile = () => {{
            const script = document.createElement('script');
            script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
            script.async = true;
            script.defer = true;
            script.onload = function() {{
                console.log('Turnstile script loaded');
                // Wait a bit for script to initialize
                setTimeout(() => {{
                    if (window.turnstile && window.turnstile.render) {{
                        try {{
                            window.turnstile.render(captchaDiv, {{
                                sitekey: '{websiteKey}',
                                {f'action: "{action}",' if action else ""}
                                {f'cdata: "{cdata}",' if cdata else ""}
                                callback: function(token) {{
                                    console.log('Turnstile solved with token:', token);
                                    // Create hidden input for token
                                    let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                                    if (!tokenInput) {{
                                        tokenInput = document.createElement('input');
                                        tokenInput.type = 'hidden';
                                        tokenInput.name = 'cf-turnstile-response';
                                        document.body.appendChild(tokenInput);
                                    }}
                                    tokenInput.value = token;
                                }},
                                'error-callback': function(error) {{
                                    console.log('Turnstile error:', error);
                                }}
                            }});
                        }} catch (e) {{
                            console.log('Turnstile render error:', e);
                        }}
                    }} else {{
                        console.log('Turnstile API not available');
                    }}
                }}, 1000);
            }};
            script.onerror = function() {{
                console.log('Failed to load Turnstile script');
            }};
            document.head.appendChild(script);
        }};
        
        // Check if Turnstile is already loaded
        if (window.turnstile) {{
            console.log('Turnstile already loaded, rendering immediately');
            try {{
                window.turnstile.render(captchaDiv, {{
                    sitekey: '{websiteKey}',
                    {f'action: "{action}",' if action else ""}
                    {f'cdata: "{cdata}",' if cdata else ""}
                    callback: function(token) {{
                        console.log('Turnstile solved with token:', token);
                        let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                        if (!tokenInput) {{
                            tokenInput = document.createElement('input');
                            tokenInput.type = 'hidden';
                            tokenInput.name = 'cf-turnstile-response';
                            document.body.appendChild(tokenInput);
                        }}
                        tokenInput.value = token;
                    }},
                    'error-callback': function(error) {{
                        console.log('Turnstile error:', error);
                    }}
                }});
            }} catch (e) {{
                console.log('Immediate render error:', e);
                loadTurnstile();
            }}
        }} else {{
            loadTurnstile();
        }}
        
        // Setup global callback
        window.onTurnstileCallback = function(token) {{
            console.log('Global turnstile callback executed:', token);
        }};
        """

        await page.evaluate(script)
        if self.debug:
            logger.debug(
                f"Browser {index}: Injected CAPTCHA directly into website with sitekey: {websiteKey}"
            )

    async def _solve_turnstile(
        self,
        task_id: str,
        url: str,
        sitekey: str,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
        locale: Optional[str] = None,
        timezone: Optional[str] = None,
        accept_language: Optional[str] = None,
    ):
        """Solve Turnstile via playwright-captcha ClickSolver on real page."""
        start_time = time.time()
        # Let Quart flush the task-id response before synchronous CDP/proxy setup.
        await asyncio.sleep(0.05)
        try:
            if task_id in self.cancelled_tasks:
                raise asyncio.CancelledError()
            sem = self.solve_semaphore
            if sem is None:
                sem = asyncio.Semaphore(max(1, int(self.thread_count or 1)))
                self.solve_semaphore = sem
            async with sem:
                if task_id in self.cancelled_tasks:
                    raise asyncio.CancelledError()
                await self._solve_turnstile_inner(
                    task_id=task_id,
                    url=url,
                    sitekey=sitekey,
                    action=action,
                    cdata=cdata,
                    proxy=proxy,
                    locale=locale,
                    timezone=timezone,
                    accept_language=accept_language,
                    start_time=start_time,
                )
        except asyncio.CancelledError:
            elapsed = round(time.time() - start_time, 3)
            logger.warning(f"Solve cancelled task={task_id[:8]} in {elapsed}s")
            await save_result(
                task_id,
                "turnstile",
                {"value": "CAPTCHA_FAIL", "status": "CANCELLED", "elapsed_time": elapsed},
            )
            raise
        except Exception as e:
            elapsed = round(time.time() - start_time, 3)
            logger.error(f"Solve exception: {e}")
            await save_result(
                task_id,
                "turnstile",
                {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed},
            )

    async def _solve_turnstile_inner(
        self,
        *,
        task_id: str,
        url: str,
        sitekey: str,
        action: Optional[str],
        cdata: Optional[str],
        proxy: Optional[str],
        locale: Optional[str],
        timezone: Optional[str],
        accept_language: Optional[str],
        start_time: float,
    ) -> None:
        """Run the actual solve under solve_semaphore."""
        try:
            logger.info(
                f"Solving turnstile task={task_id[:8]} url={url} sitekey={sitekey[:18]}..."
            )
            task_proxy = (proxy or "").strip()
            configured_proxy = os.getenv("SOLVER_PROXY", "").strip()
            proxies = load_proxy_list()
            proxy = task_proxy or configured_proxy or (random.choice(proxies) if proxies else None)
            if proxy:
                logger.info(f"task proxy: {mask_proxy(proxy)}")
            else:
                logger.warning("no proxy for solver; may fail on x.ai")

            # Browser mode: SOLVER_BROWSER_MODE > SOLVER_HEADLESS > --no-headless
            mode = (os.getenv("SOLVER_BROWSER_MODE") or "").strip().lower() or None
            token = await solve_turnstile_token(
                url=url,
                sitekey=sitekey,
                action=action,
                cdata=cdata,
                headless=self.headless,
                timeout_seconds=int(os.getenv("LOCAL_SOLVER_TIMEOUT_SECONDS", "30") or "30"),
                proxy=proxy,
                locale=locale,
                timezone=timezone,
                accept_language=accept_language,
                mode=mode,
                worker_size=self.thread_count,
            )
            elapsed = round(time.time() - start_time, 3)
            if token and token != "CAPTCHA_FAIL" and len(token) > 20:
                logger.success(
                    f"Solved captcha {COLORS.get('MAGENTA')}{token[:12]}{COLORS.get('RESET')} in {elapsed}s"
                )
                await save_result(
                    task_id, "turnstile", {"value": token, "elapsed_time": elapsed}
                )
            else:
                logger.error(f"Solve failed in {elapsed}s")
                await save_result(
                    task_id,
                    "turnstile",
                    {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed},
                )
        except asyncio.CancelledError:
            raise

    async def process_turnstile(self):
        """Handle the /turnstile endpoint requests."""
        url = request.args.get("url")
        sitekey = request.args.get("sitekey")
        action = request.args.get("action")
        cdata = request.args.get("cdata")
        proxy = request.args.get("proxy")
        locale = request.args.get("locale")
        timezone = request.args.get("timezone")
        accept_language = request.args.get("accept_language")

        if not url or not sitekey:
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_WRONG_PAGEURL",
                    "errorDescription": "Both 'url' and 'sitekey' are required",
                }
            ), 200

        task_id = str(uuid.uuid4())
        await save_result(
            task_id,
            "turnstile",
            {
                "status": "CAPTCHA_NOT_READY",
                "createTime": int(time.time()),
                "url": url,
                "sitekey": sitekey,
                "action": action,
                "cdata": cdata,
                "proxy": mask_proxy(proxy),
                "locale": locale,
                "timezone": timezone,
                "accept_language": accept_language,
            },
        )

        try:
            task = asyncio.create_task(
                self._solve_turnstile(
                    task_id=task_id,
                    url=url,
                    sitekey=sitekey,
                    action=action,
                    cdata=cdata,
                    proxy=proxy,
                    locale=locale,
                    timezone=timezone,
                    accept_language=accept_language,
                )
            )
            self.active_tasks[task_id] = task

            def _forget(_task, _task_id=task_id):
                self.active_tasks.pop(_task_id, None)
                self.cancelled_tasks.discard(_task_id)

            task.add_done_callback(_forget)

            if self.debug:
                logger.debug(f"Request completed with taskid {task_id}.")
            return jsonify({"errorId": 0, "taskId": task_id}), 200
        except Exception as e:
            logger.error(f"Unexpected error processing request: {str(e)}")
            return jsonify(
                {"errorId": 1, "errorCode": "ERROR_UNKNOWN", "errorDescription": str(e)}
            ), 200

    async def cancel_task(self):
        """Cancel one queued/running Turnstile task."""
        task_id = request.args.get("id") or request.args.get("taskId")
        if not task_id:
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                    "errorDescription": "Invalid task ID/Request parameter",
                }
            ), 200

        task_id = str(task_id)
        self.cancelled_tasks.add(task_id)
        task = self.active_tasks.get(task_id)
        cancelled = False
        if task is not None and not task.done():
            task.cancel()
            cancelled = True
        await save_result(
            task_id,
            "turnstile",
            {
                "value": "CAPTCHA_FAIL",
                "status": "CANCELLED",
                "elapsed_time": 0,
            },
        )
        return jsonify({"errorId": 0, "taskId": task_id, "cancelled": cancelled}), 200

    async def cancel_all_tasks(self):
        """Cancel all queued/running Turnstile tasks in this solver process."""
        task_ids = list(self.active_tasks.keys())
        for task_id in task_ids:
            self.cancelled_tasks.add(task_id)
            task = self.active_tasks.get(task_id)
            if task is not None and not task.done():
                task.cancel()
            await save_result(
                task_id,
                "turnstile",
                {
                    "value": "CAPTCHA_FAIL",
                    "status": "CANCELLED",
                    "elapsed_time": 0,
                },
            )
        return jsonify({"errorId": 0, "cancelled": len(task_ids)}), 200

    async def get_result(self):
        """Return solved data"""
        task_id = request.args.get("id")

        if not task_id:
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                    "errorDescription": "Invalid task ID/Request parameter",
                }
            ), 200

        result = await load_result(task_id)
        if not result:
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                    "errorDescription": "Task not found",
                }
            ), 200

        if result == "CAPTCHA_NOT_READY" or (
            isinstance(result, dict) and result.get("status") == "CAPTCHA_NOT_READY"
        ):
            return jsonify({"status": "processing"}), 200

        if isinstance(result, dict) and result.get("value") == "CAPTCHA_FAIL":
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                    "errorDescription": "Workers could not solve the Captcha",
                }
            ), 200

        if (
            isinstance(result, dict)
            and result.get("value")
            and result.get("value") != "CAPTCHA_FAIL"
        ):
            return jsonify(
                {
                    "errorId": 0,
                    "status": "ready",
                    "solution": {"token": result["value"]},
                }
            ), 200
        else:
            return jsonify(
                {
                    "errorId": 1,
                    "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                    "errorDescription": "Workers could not solve the Captcha",
                }
            ), 200

    @staticmethod
    async def index():
        """Serve the API documentation page."""
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Turnstile Solver API</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-900 text-gray-200 min-h-screen flex items-center justify-center">
                <div class="bg-gray-800 p-8 rounded-lg shadow-md max-w-2xl w-full border border-red-500">
                    <h1 class="text-3xl font-bold mb-6 text-center text-red-500">Welcome to Turnstile Solver API</h1>

                    <p class="mb-4 text-gray-300">To use the turnstile service, send a GET request to 
                       <code class="bg-red-700 text-white px-2 py-1 rounded">/turnstile</code> with the following query parameters:</p>

                    <ul class="list-disc pl-6 mb-6 text-gray-300">
                        <li><strong>url</strong>: The URL where Turnstile is to be validated</li>
                        <li><strong>sitekey</strong>: The site key for Turnstile</li>
                    </ul>

                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">Example usage:</p>
                        <code class="text-sm break-all text-red-300">/turnstile?url=https://example.com&sitekey=sitekey</code>
                    </div>


                    <div class="bg-gray-700 p-4 rounded-lg mb-6">
                        <p class="text-gray-200 font-semibold mb-3">📢 Connect with Us</p>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                📢 <strong>Channel:</strong> 
                                <a href="https://t.me/D3_vin" class="text-red-300 hover:underline">https://t.me/D3_vin</a> 
                                - Latest updates and releases
                            </p>
                            <p class="text-gray-300">
                                💬 <strong>Chat:</strong> 
                                <a href="https://t.me/D3vin_chat" class="text-red-300 hover:underline">https://t.me/D3vin_chat</a> 
                                - Community support and discussions
                            </p>
                            <p class="text-gray-300">
                                📁 <strong>GitHub:</strong> 
                                <a href="https://github.com/D3-vin" class="text-red-300 hover:underline">https://github.com/D3-vin</a> 
                                - Source code and development
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Turnstile API Server")

    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Run the browser with GUI (disable headless mode). By default, headless mode is enabled.",
    )
    parser.add_argument(
        "--useragent",
        type=str,
        help="User-Agent string (if not specified, random configuration is used)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable or disable debug mode for additional logging and troubleshooting information (default: False)",
    )
    parser.add_argument(
        "--browser_type",
        type=str,
        default="chromium",
        help="Specify the browser type for the solver. Supported options: chromium, chrome, msedge, camoufox (default: chromium)",
    )
    parser.add_argument(
        "--thread",
        type=int,
        default=2,
        help="Set the number of browser threads to use for multi-threaded mode. Increasing this will speed up execution but requires more resources (default: 2)",
    )
    parser.add_argument(
        "--proxy",
        action="store_true",
        help="Enable proxy support for the solver (Default: False)",
    )
    parser.add_argument(
        "--random",
        action="store_true",
        help="Use random User-Agent and Sec-CH-UA configuration from pool",
    )
    parser.add_argument(
        "--browser",
        type=str,
        help="Specify browser name to use (e.g., chrome, firefox)",
    )
    parser.add_argument(
        "--version", type=str, help="Specify browser version to use (e.g., 139, 141)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Specify the IP address where the API solver runs. (Default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=str,
        default="5072",
        help="Set the port for the API solver to listen on. (Default: 5072)",
    )
    return parser.parse_args()


def create_app(
    headless: bool,
    useragent: str,
    debug: bool,
    browser_type: str,
    thread: int,
    proxy_support: bool,
    use_random_config: bool,
    browser_name: str,
    browser_version: str,
) -> Quart:
    server = TurnstileAPIServer(
        headless=headless,
        useragent=useragent,
        debug=debug,
        browser_type=browser_type,
        thread=thread,
        proxy_support=proxy_support,
        use_random_config=use_random_config,
        browser_name=browser_name,
        browser_version=browser_version,
    )
    return server.app


if __name__ == "__main__":
    args = parse_args()
    browser_types = [
        "chromium",
        "chrome",
        "msedge",
        "camoufox",
    ]
    if args.browser_type not in browser_types:
        logger.error(
            f"Unknown browser type: {COLORS.get('RED')}{args.browser_type}{COLORS.get('RESET')} Available browser types: {browser_types}"
        )
    else:
        # Auto-enable proxy if proxies.txt / HTTP_PROXY exists (free solver needs it for x.ai)
        auto_proxy = args.proxy
        if not auto_proxy:
            if os.path.exists(os.path.join(os.getcwd(), "proxies.txt")) or os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY"):
                auto_proxy = True
                logger.info("Auto-enabled proxy support (proxies.txt / HTTP_PROXY detected)")

        # Headless selection:
        # 1) SOLVER_HEADLESS env wins when present
        # 2) else CLI --no-headless / default
        # Note: Cloudflare often rejects pure headless (600010). Headed is safer.
        env_headless = os.getenv("SOLVER_HEADLESS")
        if env_headless is not None:
            headless_mode = env_headless.strip().lower() in {"1", "true", "yes", "on"}
        else:
            headless_mode = not args.no_headless

        app = create_app(
            headless=headless_mode,
            debug=args.debug,
            useragent=args.useragent,
            browser_type=args.browser_type,
            thread=args.thread,
            proxy_support=auto_proxy,
            use_random_config=args.random,
            browser_name=args.browser,
            browser_version=args.version,
        )
        # Reduce default thread if user left default 8 for local free use
        mode_env = (os.getenv("SOLVER_BROWSER_MODE") or ("headless" if headless_mode else "headed")).strip()
        logger.info(f"Solver starting host={args.host} port={args.port} threads={args.thread} proxy={auto_proxy} headless={headless_mode} mode={mode_env}")
        atexit.register(shutdown_worker_pool)
        app.run(host=args.host, port=int(args.port))
