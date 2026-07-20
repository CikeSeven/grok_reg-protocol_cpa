# 本地 Turnstile 降级打码（api_solver）

协议注册主路径：YesCaptcha（config `yescaptcha_key`）。
当未配置 key 或 YesCaptcha 失败时，会回退请求本机：

```text
POST http://127.0.0.1:5072/turnstile
GET  http://127.0.0.1:5072/result?id=...
```

## 其他电脑怎么用

1. 安装依赖（建议单独 venv）：

```bash
pip install -r local_solver/requirements.txt
# Chromium for patchright/playwright
python -m patchright install chromium
```

2. 启动本地 solver（默认端口 5072，与 config `protocol_solver_url` 一致）：

```bash
cd local_solver
python api_solver.py --thread 1 --port 5072
```

Windows 也可尝试：

```bat
TurnstileSolver.bat
```

3. 注册机侧保持：

```json
"protocol_solver_url": "http://127.0.0.1:5072",
"yescaptcha_key": ""
```

空 `yescaptcha_key` 时会直接走本地 solver。
有 YesCaptcha key 时优先云端，失败再降级本地。

## 目录文件

- `api_solver.py` HTTP 打码服务入口
- `turnstile_engine.py` 实际解题引擎
- `db_results.py` 任务结果缓存
- `browser_configs.py` UA/浏览器配置池
- `proxies.txt.example` 可选代理模板（可复制为 proxies.txt）
- `requirements.txt` 依赖（含注册机 + solver）

注意：本地 solver 需要可用的 Chromium/Chrome，体积大头在浏览器，不在这几个 py 文件。
