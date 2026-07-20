# Grok Reg WebUI 设计

日期：2026-07-19

## 目标

为 `grok_reg-protocol_cpa` 提供本地完整运维 WebUI：

- 批量注册控制
- 账号账本管理
- CPA 文件管理与补 mint
- Hotmail 邮箱凭证管理
- 配置中心
- 任务记录与实时日志

视觉语言参考 `gpt_oauth`（深色侧栏、metrics、表格、状态 pill、任务抽屉、dialog），业务导航与数据模型按本项目定制，不照搬 OAuth 授权台。

## 决策

| 项 | 选择 |
|---|---|
| 范围 | 完整运维台 |
| 数据层 | 继续用现有文件账本 |
| 后端 | FastAPI + 进程内 JobRunner |
| 绑定 | 默认 `127.0.0.1:8787` |
| 存储 | 无 SQLite |

## 文件映射

| 业务 | 文件 |
|---|---|
| 配置 | `config.json` |
| 账号账本 | `accounts_cli.txt`（`email----password----sso`） |
| 邮箱凭证 | `mail_credentials.txt`（Hotmail 四段） |
| CPA 认证 | `cpa_auths/xai-*.json` |

## 包结构

```text
webui/
  __init__.py
  __main__.py
  server.py
  app.py
  store.py
  jobs.py
  static/
    index.html
    app.css
    app.js
    ui-icons.svg
```

## 页面

1. **注册控制**：启动/停止注册、extra/threads/mint/headless、实时 stats 与日志
2. **账号账本**：搜索筛选、SSO/CPA 状态、导出删除
3. **CPA 管理**：文件列表、补 mint、下载、删除
4. **邮箱凭证**：Hotmail 四段导入/删除/计数
5. **配置中心**：常用配置表单 + 原始 JSON 编辑
6. **任务抽屉**：register / backfill 历史、进度、停止

## API 概览

- `GET /api/overview` 顶部 metrics
- `GET/DELETE /api/accounts`、`POST /api/accounts/export`
- `GET/DELETE /api/cpa`、`GET /api/cpa/download`
- `GET/POST/DELETE /api/mail-credentials`
- `GET/PUT /api/config`
- `POST /api/jobs/register`、`POST /api/jobs/backfill`
- `GET /api/jobs`、`GET /api/jobs/{id}`、`POST /api/jobs/{id}/stop`
- `GET /api/jobs/{id}/events` SSE 日志流

## JobRunner

- 同时只允许一个重型任务（register 或 backfill）
- 复用 `register_cli` worker / `cpa_xai.mint_and_export`
- 支持取消：cancel token + 浏览器 shutdown
- 日志环形缓冲，前端 SSE / 轮询均可

## 启动

```bash
uv run python -m webui --host 127.0.0.1 --port 8787
```

## 非目标

- 远程多用户鉴权
- SQLite 迁移
- 替换现有 CLI / ttk GUI
