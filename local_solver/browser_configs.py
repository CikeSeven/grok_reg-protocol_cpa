"""浏览器指纹配置，为 API Solver 提供 User-Agent 和 Sec-CH-UA 生成"""

import random


class BrowserConfig:
    """浏览器指纹配置生成器"""

    @staticmethod
    def get_random_browser_config(browser_type=None):
        """生成随机浏览器配置，返回 (browser_name, version, user_agent, sec_ch_ua)"""
        versions = ["120.0.0.0", "121.0.0.0", "122.0.0.0", "124.0.0.0"]
        ver = random.choice(versions)
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"
        sec_ch_ua = f'"Not(A:Brand";v="99", "Google Chrome";v="{ver.split(".")[0]}", "Chromium";v="{ver.split(".")[0]}"'
        return "chrome", ver, ua, sec_ch_ua

    @staticmethod
    def get_browser_config(name, version):
        """根据指定浏览器名和版本生成配置，返回 (user_agent, sec_ch_ua)"""
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
        sec_ch_ua = f'"Google Chrome";v="{version}", "Chromium";v="{version}"'
        return ua, sec_ch_ua
