# IT 终端设备数据加密防泄漏系统（增强版 v2.0）

基于 Python 的准生产级数据防泄漏（DLP）系统，面向企业内部终端设备的数据安全管控需求，提供文件自动透明加密、安全解密、多通道外发拦截、数字水印、审批流程和集中管理后台等完整能力。

## 目录

- [核心能力](#核心能力)
- [系统架构](#系统架构)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [安装部署](#安装部署)
  - [环境要求](#环境要求)
  - [依赖安装](#依赖安装)
  - [服务端部署](#服务端部署)
  - [Agent 部署](#agent-部署)
- [模块详解](#模块详解)
  - [服务端 (server/)](#服务端-server)
  - [Agent 核心 (agent/core.py)](#agent-核心-agentcorepy)
  - [文件监控 (agent/watcher.py)](#文件监控-agentwatcherpy)
  - [剪贴板守卫 (agent/clipboard_guard.py)](#剪贴板守卫-agentclipboard_guardpy)
  - [USB 守卫 (agent/usb_guard.py)](#usb-守卫-agentusb_guardpy)
  - [网络代理 (agent/net_guard.py)](#网络代理-agentnet_guardpy)
  - [进程校验 (agent/process_verify.py)](#进程校验-agentprocess_verifypy)
  - [系统托盘 (agent/tray_app.py)](#系统托盘-agenttray_apppy)
  - [加密工具 (common/crypto_utils.py)](#加密工具-commoncrypto_utilspy)
  - [数字水印 (common/watermark.py)](#数字水印-commonwatermarkpy)
- [API 参考](#api-参考)
- [配置参考](#配置参考)
- [工作流程](#工作流程)
- [安全设计](#安全设计)
- [与原型对比](#与原型对比)
- [生产部署建议](#生产部署建议)
- [故障排查](#故障排查)
- [开发指南](#开发指南)
- [许可证](#许可证)

---

## 核心能力

| 领域 | 能力 | 实现方式 |
|---|---|---|
| **数据加密** | 文件落地自动加密 | watchdog 目录监控 + AES-256-GCM 即时加密 |
| **数据加密** | 安全解密查看 | 解密到安全临时文件，进程退出后 3-pass 擦除 |
| **数据加密** | 密钥生命周期管理 | 服务端 KMS 统一托管，本地 Argon2id 加密缓存（缺依赖时 PBKDF2 兜底） |
| **通道管控** | 剪贴板拦截 | Windows API 剪贴板查看器钩子，实时清空黑名单进程粘贴 |
| **通道管控** | USB 拷贝阻断 | watchdog 监控可移动磁盘，检测 .itdlp 文件立即删除 |
| **通道管控** | 网络上传拦截 | 本地 HTTP 代理层检测受控文件魔数并返回 403 |
| **通道管控** | 进程完整性校验 | 真实路径验证 + 可选 Windows 数字签名校验 |
| **外发管控** | 审批流程 | 外发申请 → 管理员审批 → 可选添加水印 |
| **水印溯源** | 多格式水印 | 文本/图片/PDF 外发时自动叠加用户+时间水印 |
| **审计追溯** | 全操作审计 | 加密/解密/外发/拦截等全部操作实时上报 |
| **离线保护** | 离线宽限期 | 策略缓存 + 超时自动锁定，防止离线绕过 |
| **集中管理** | Web 管理后台 | 终端管理 / 审计日志 / 外发审批 / 策略在线编辑 |

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        管理控制中心 (server/)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ FastAPI REST │  │   Admin SPA  │  │   SQLite 持久化存储     │ │
│  │   API 服务    │  │  (admin.html)│  │  (终端/密钥/审计/审批)   │ │
│  └──────┬───────┘  └──────────────┘  └────────────────────────┘ │
│         │                                                        │
│         │  HTTP/JSON (策略下发 · KMS 授权 · 审计上报 · 审批)      │
│         ▼                                                        │
├─────────────────────────────────────────────────────────────────┤
│                     终端 Agent (agent/)                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   系统托盘 (tray_app.py)                    │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │   │
│  │  │ 文件监控  │ │ 剪贴板   │ │ USB      │ │ 网络代理     │  │   │
│  │  │ watcher  │ │ guard    │ │ guard    │ │ net_guard   │  │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬──────┘  │   │
│  │       │             │            │              │          │   │
│  │       └─────────────┴────────────┴──────────────┘          │   │
│  │                          │                                  │   │
│  │                   ┌──────▼──────┐                          │   │
│  │                   │  Agent 核心  │                          │   │
│  │                   │  (core.py)  │                          │   │
│  │                   └──────┬──────┘                          │   │
│  │                          │                                  │   │
│  └──────────────────────────┼──────────────────────────────────┘   │
│                             │                                      │
│  ┌──────────────────────────┼──────────────────────────────────┐   │
│  │              公共模块 (common/)                               │   │
│  │  ┌──────────────────┐    ┌──────────────────┐               │   │
│  │  │   crypto_utils   │    │    watermark     │               │   │
│  │  │ AES-256-GCM      │    │  文本/图片/PDF    │               │   │
│  │  │ Argon2/PBKDF2 KDF │    │  外发自动水印     │               │   │
│  │  │ 安全擦除          │    │                  │               │   │
│  │  └──────────────────┘    └──────────────────┘               │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 数据流概览

```
明文文件 ──[落地监控]──▶ 自动 AES-256-GCM 加密 ──▶ .itdlp 密文
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            白名单进程授权打开      非授权进程/通道拦截
            (安全临时文件)         (剪贴板/USB/网络)
                    │
                    ▼
            进程退出自动擦除
                    │
            ┌───────┴───────┐
            ▼               ▼
       正常关闭         外发审批流程
                       (加水印后导出)
```

## 技术栈

| 层级 | 技术 | 用途 |
|---|---|---|
| 服务端框架 | FastAPI + Uvicorn | REST API + Admin 静态页面 |
| 数据库 | SQLite3 | 终端、密钥、审计、审批持久化 |
| 加密算法 | AES-256-GCM | 文件对称加密 |
| 密钥派生 | Argon2id / PBKDF2 兜底 | 本地主密钥派生 |
| 文件监控 | watchdog | 目录自动加密 + U 盘监控 |
| Windows API | pywin32 | 剪贴板钩子、系统托盘 |
| 进程管理 | psutil | 进程路径获取与校验 |
| 网络代理 | aiohttp | HTTP 代理层上传拦截 |
| 图像处理 | Pillow (PIL) | 图片水印叠加 |
| PDF 处理 | pikepdf + reportlab | PDF 可视水印叠加 |
| 系统托盘 | pystray | 后台常驻托盘图标 |

## 快速开始

### 一键演示

```bash
cd new2
pip install -r requirements.txt
python demo.py
```

该脚本会自动启动服务端、执行完整演示流程并输出每一步的结果。演示结束后按 Enter 退出。

### 手动运行服务端

```bash
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

访问管理后台：`http://127.0.0.1:8000/admin`

### 手动运行托盘客户端

```bash
python -m agent.tray_app
```

托盘客户端会自动启动：
- 受控目录监控（默认 `Documents/受控资料`）
- 剪贴板守卫（拦截复制到微信/QQ 等）
- USB 守卫（阻止 `.itdlp` 文件写入 U 盘）
- 网络代理（拦截上传流量，代理端口 3128）
- `.itdlp` 文件关联（员工电脑上双击密文即可透明打开）

### 双击透明打开机制

在防泄漏员工电脑上，托盘客户端启动时会为当前用户注册 `.itdlp` 文件关联。双击 `.itdlp` 后，Windows 会调用 `agent/file_opener.py`，由本机 Agent 使用本地密钥缓存或服务端 KMS 授权解密到随机临时文件，并按原文件扩展名交给默认应用打开。应用关闭后，临时明文会被安全擦除。

把 `.itdlp` 文件复制到外部电脑后，外部电脑没有该文件关联、没有本机密钥缓存，也无法通过 KMS 授权，因此只能看到 AES-GCM 加密后的二进制密文内容。

### Agent 命令行

```bash
# 注册终端并同步策略
python -m agent.core register

# 加密受控文件（安全擦除原明文）
python -m agent.core protect ./doc.txt

# 白名单进程授权打开（安全临时文件方式）
python -m agent.core open ./doc.txt.itdlp --process notepad.exe

# 注册 .itdlp 双击透明打开关联（员工电脑执行一次即可，托盘启动也会自动修复）
python -m agent.core install-association

# 双击关联实际调用的透明打开命令
python -m agent.core transparent-open ./doc.txt.itdlp

# 审批/测试用：解密到指定输出文件
python -m agent.core decrypt-to ./doc.txt.itdlp ./doc.preview.txt

# 非白名单进程将被拒绝
python -m agent.core open ./doc.txt.itdlp --process hacker.exe

# 通道管控检查
python -m agent.core copy-check --source ./doc.txt.itdlp --target wechat.exe
python -m agent.core screenshot-check --active-file ./doc.txt.itdlp
python -m agent.core usb-check --operation copy_out --file ./doc.txt.itdlp
python -m agent.core upload-check --file ./doc.txt.itdlp --port 443

# 发起外发审批申请
python -m agent.core export-request ./doc.txt.itdlp --reason "需发送给客户"
```

## 安装部署

### 环境要求

- **操作系统**：Windows 10/11（剪贴板守卫和 USB 守卫依赖 Windows API）
  - 服务端可在 Linux/macOS 运行（通道管控模块除外）
- **Python**：3.10 及以上
- **内存**：Agent 常驻约 80-150MB，服务端约 50-100MB
- **磁盘**：约 500MB（含依赖）

### 依赖安装

```bash
cd new2
pip install -r requirements.txt
```

> **注意**：`pywin32` 仅在 Windows 平台安装。Linux/macOS 部署服务端时可跳过该依赖。

### 服务端部署

1. **单机开发/演示**：
   ```bash
   python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
   ```

2. **局域网部署**：
   ```bash
   python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
   ```
   其他机器通过 `http://<server-ip>:8000` 访问。Agent 需设置环境变量：
   ```bash
   set ITDLP_SERVER=http://192.168.1.100:8000
   ```

3. **生产部署**（推荐）：
   ```bash
   # 使用 gunicorn + uvicorn workers
   pip install gunicorn
   gunicorn server.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

   # 前面加 Nginx 反向代理 + HTTPS
   ```

### Agent 部署

1. **手动运行**：
   ```bash
   python -m agent.tray_app
   ```

2. **开机自启动**：
   - 创建快捷方式到 `shell:startup`
   - 或注册为 Windows 服务（推荐生产环境）：
     ```powershell
     # 使用 nssm 注册服务
     nssm install IT-DLP-Agent python -m agent.tray_app
     ```

3. **组策略下发**：
   - 将 Agent 目录部署到 `%ProgramFiles%\IT-DLP\`
   - 通过组策略下发开机启动脚本
   - 配置系统代理指向 `127.0.0.1:3128`

## 模块详解

### 服务端 (server/)

**`server/main.py`** — 管理控制中心核心，提供完整 REST API：

| 端点 | 方法 | 说明 |
|---|---|---|
| `/health` | GET | 健康检查 |
| `/admin` | GET | 管理后台 SPA |
| `/api/terminals/register` | POST | 终端注册 |
| `/api/policies/{terminal_id}` | GET | 获取策略 |
| `/api/kms/keys` | POST | 创建数据密钥 |
| `/api/kms/grant` | POST | 授权密钥使用 |
| `/api/audit/logs` | POST | 上报审计日志 |
| `/api/audit/logs` | GET | 查询审计日志 |
| `/api/export/requests` | POST | 创建外发申请 |
| `/api/export/requests/{id}/approve` | POST | 审批外发申请 |
| `/api/admin/terminals` | GET | 终端列表 |
| `/api/admin/export-requests` | GET | 全部外发申请 |
| `/api/admin/policy` | GET/PUT | 查看/编辑当前策略 |
| `/api/admin/stats` | GET | 管理后台统计 |

**`server/admin.html`** — 单页管理后台，包含四个面板：
- **终端管理**：查看注册终端、在线状态
- **审计日志**：实时查看所有操作记录
- **外发审批**：审批/拒绝外发申请
- **策略配置**：查看、编辑并下发当前生效的安全策略

### Agent 核心 (agent/core.py)

`EndpointAgent` 类封装全部核心逻辑：

- **`register()`** — 向服务端注册终端，同步策略
- **`sync_policy()`** — 拉取最新策略，离线时检查宽限期
- **`protect_file()`** — 从 KMS 获取密钥，加密文件，安全擦除原明文
- **`open_file_secure()`** — 解密到安全临时文件，启动授权进程，等待退出后擦除
- **`decrypt_to_file_for_approval()`** — 审批/自动化测试场景解密到指定输出文件
- **`clipboard_check()`** — 检查剪贴板目标进程是否在禁止列表
- **`screenshot_check()`** — 检查当前活动窗口是否打开了受控文件
- **`usb_check()`** — 检查 USB 操作是否被策略禁止
- **`network_upload_check()`** — 检查网络上传是否涉及受控文件
- **`create_export_request()`** — 发起外发解密审批
- **`audit()`** — 向服务端上报操作审计（离线时写本地日志）

### 文件监控 (agent/watcher.py)

- 基于 `watchdog` 实现目录实时监控
- `AutoEncryptHandler` 检测受控扩展名文件创建/修改
- 内置 2 秒防抖避免重复处理
- 自动加密后安全擦除原明文
- 默认监控目录：`%USERPROFILE%/Documents/受控资料`
- 可通过命令行参数指定多个监控目录

### 剪贴板守卫 (agent/clipboard_guard.py)

- 注册为 Windows 剪贴板查看器（Clipboard Viewer）
- 监听 `WM_DRAWCLIPBOARD` 消息
- 检测前台窗口进程，若在黑名单中则清空剪贴板
- 默认黑名单：微信、QQ、Telegram
- 支持自定义拦截回调（如托盘通知）

### USB 守卫 (agent/usb_guard.py)

- 通过 `wmic` 枚举所有可移动磁盘
- 使用 watchdog 监控 U 盘根目录
- 检测到 `.itdlp` 文件写入时立即删除
- 每 5 秒刷新一次可移动磁盘列表
- 上报审计日志到服务端

### 网络代理 (agent/net_guard.py)

- 在本地 `127.0.0.1:3128` 启动 HTTP 代理
- 拦截层检测请求体中的 `ITDLPENC2` 魔数
- 检测 URL 中的 `.itdlp` 扩展名
- 匹配到受控特征返回 `403 Forbidden`
- 正常流量透明转发到目标服务器

### 进程校验 (agent/process_verify.py)

- **`get_process_path(pid)`** — 通过 psutil 获取进程真实 exe 路径
- **`verify_process_path(pid, expected_names)`** — 校验进程名是否在白名单
- **`verify_digital_signature(file_path)`** — 调用 Windows `WinVerifyTrust` API 校验 PE 数字签名
- **`verify_process_authorized(pid, allowed_names, check_signature)`** — 综合校验

### 系统托盘 (agent/tray_app.py)

- 基于 `pystray` 实现 Windows 系统托盘常驻
- 右键菜单：状态信息、加密文件、授权打开、同步策略、管理后台、退出
- 定时 10 秒刷新菜单状态文本
- 拦截通知通过托盘气泡弹出
- 整合所有守卫模块统一启停

### 加密工具 (common/crypto_utils.py)

- **加密算法**：AES-256-GCM（认证加密，防篡改）
- **密钥派生**：优先用 Argon2id 从密码派生 256-bit 主密钥；未安装 `argon2-cffi` 时使用 PBKDF2-SHA256 兜底
- **文件格式**：`MAGIC(8B) + header_len(4B) + header_json(可变) + nonce(12B) + ciphertext(可变)`
- **安全擦除**：3-pass（0x00 → 0xFF → 随机）覆写后删除
- **安全临时文件**：`SecureTempFile` 上下文管理器，退出自动擦除
- **本地密钥保护**：数据密钥用 KDF 派生密钥加密存储，内存使用后即时清零

### 数字水印 (common/watermark.py)

- **文本文件**（`.txt/.csv/.log`）：头部添加 `[CONFIDENTIAL | User:xxx | timestamp]` 标记
- **图片文件**（`.png/.jpg/.bmp/.gif` 等）：四角 + 中心叠加半透明红色水印文字
- **PDF 文件**（`.pdf`）：每页添加 FreeText 注释水印
- **其他格式**：生成同目录 `.watermark.txt` 旁注文件
- 水印内容包含：机密级别 + 用户 ID + 时间戳 + 审批人信息

## API 参考

### 终端注册

```http
POST /api/terminals/register
Content-Type: application/json

{
  "terminal_id": "TERM-PC001-A1B2C3",
  "hostname": "PC001",
  "user_id": "zhangsan",
  "department": "研发中心"
}
```

响应：
```json
{
  "registered": true,
  "terminal_id": "TERM-PC001-A1B2C3",
  "policy": { ... }
}
```

### 创建数据密钥

```http
POST /api/kms/keys
Content-Type: application/json

{
  "terminal_id": "TERM-PC001-A1B2C3",
  "owner_id": "zhangsan",
  "classification": "internal"
}
```

### 密钥授权

```http
POST /api/kms/grant
Content-Type: application/json

{
  "key_id": "KEY-ABC123",
  "terminal_id": "TERM-PC001-A1B2C3",
  "process_name": "notepad.exe",
  "user_id": "zhangsan",
  "purpose": "open"
}
```

### 外发申请审批

```http
POST /api/export/requests/{request_id}/approve
Content-Type: application/json

{
  "approver_id": "admin",
  "approved": true,
  "comment": "同意外发，已加水印"
}
```

## 配置参考

### 默认策略 (`DEFAULT_POLICY`)

```python
{
    "policy_id": "POLICY-DEFAULT-001",
    "version": 2,
    "offline_grace_hours": 72,          # 离线宽限期（小时）
    "controlled_extensions": [           # 受控文件扩展名
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".dwg", ".pdf", ".txt", ".png", ".jpg", ".csv"
    ],
    "process_whitelist": [               # 进程白名单
        "winword.exe", "excel.exe", "powerpnt.exe",
        "acad.exe", "notepad.exe", "python.exe"
    ],
    "clipboard_forbidden_targets": [     # 剪贴板黑名单
        "wechat.exe", "qq.exe", "telegram.exe",
        "chrome.exe", "msedge.exe"
    ],
    "usb_mode": "readonly",              # USB 模式: readonly / disabled / full
    "network_upload_control": true,      # 启用网络上传拦截
    "watermark_enabled": true,           # 启用外发水印
    "print_control": "audit_and_approve", # 打印控制
    "signature_check": false             # 是否校验进程数字签名
}
```

### Agent 配置 (`agent_state/agent_config.json`)

```json
{
  "server_url": "http://127.0.0.1:8000",
  "terminal_id": "TERM-PC001-A1B2C3",
  "user_id": "zhangsan",
  "department": "研发中心",
  "hostname": "PC001",
  "local_password": ""
}
```

### 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `ITDLP_SERVER` | 服务端地址 | `http://127.0.0.1:8000` |
| `PORT` | 服务端监听端口 | `8000` |

## 工作流程

### 文件加密流程

```
1. 用户将明文文件放入受控目录（或拖入监控目录）
2. watcher 检测到新文件 → 通知 Agent
3. Agent 向服务端 KMS 申请数据密钥
4. 服务端生成 AES-256 密钥，持久化存储，返回 key_id
5. Agent 使用密钥加密文件，输出 .itdlp 密文
6. Agent 对原明文执行 3-pass 安全擦除并删除
7. Agent 上报加密审计日志
```

### 安全解密流程

```
1. 用户右键托盘 → "授权打开" → 选择 .itdlp 文件
2. Agent 解析加密文件头，提取 key_id
3. Agent 校验调用进程是否在白名单中
4. Agent 从本地加密缓存恢复密钥（或向 KMS 申请授权）
5. Agent 解密到安全临时文件（SecureTempFile）
6. Agent 使用授权进程打开临时文件
7. 等待进程退出
8. 对临时文件执行 3-pass 安全擦除并删除
```

### 外发审批流程

```
1. 用户发起外发申请：python -m agent.core export-request file.itdlp --reason "..."
2. 服务端创建审批记录，状态=pending
3. 管理员在 Admin 后台查看申请
4. 管理员审批通过/拒绝
5. 若通过且启用水印：自动对文件添加水印
6. 返回水印文件路径供下载
```

## 安全设计

### 加密体系

- **算法选择**：AES-256-GCM，提供机密性 + 完整性 + 认证
- **密钥管理**：每个文件独立数据密钥，服务端 KMS 统一托管
- **本地缓存**：数据密钥经 Argon2id/PBKDF2 派生密钥加密后存储，不以明文落盘
- **内存安全**：密钥使用后立即通过 `secure_zero` 覆写清零

### 文件擦除

- 3-pass 覆写：0x00 → 0xFF → 随机字节
- 每次覆写后 `fsync` 确保写入物理介质
- 删除操作在 finally 块中保证执行

### 离线保护

- 策略缓存到本地 `policy_cache.json`
- 离线时检查宽限期（默认 72 小时）
- 超时后所有受控操作被拒绝
- 离线审计日志缓存在本地，上线后批量上报

### 进程校验

- 不依赖进程名字符串比对
- 通过 psutil 获取进程真实可执行文件路径
- 可选 Windows 数字签名验证（WinVerifyTrust API）

### 已知局限

- **透明加密**：Python 用户态无法实现真正的内核级透明加密（需 Windows Minifilter 驱动），当前方案为目录监控自动加密
- **剪贴板守卫**：依赖 Windows Clipboard Viewer Chain，无法拦截通过 `SendInput` 等 API 的注入
- **网络代理**：需要配置系统代理或应用代理，无法拦截不走代理的流量
- **单机部署**：当前 SQLite 不适合多服务端集群，高并发场景需迁移至 PostgreSQL

## 与原型对比

| 能力 | 原版（v1） | 增强版（v2） |
|---|---|---|
| 文件加密方式 | 手动执行命令 | watchdog 目录监控自动加密 |
| 解密方式 | 明文落到工作目录 | 安全临时文件 + 进程退出后 3-pass 擦除 |
| 剪贴板管控 | 模拟检查（仅返回结果） | Windows API 剪贴板查看器实时清空 |
| USB 管控 | 模拟检查 | watchdog 监控可移动磁盘并删除密文 |
| 网络管控 | 模拟检查 | 本地 HTTP 代理层检测魔数阻断 |
| 进程校验 | 仅比对进程名字符串 | 校验真实路径 + 可选数字签名 |
| 本地密钥缓存 | 明文 JSON 存储 | KDF 派生主密钥加密后存储 |
| 数字水印 | 无 | 文本/图片/PDF 自动水印 |
| 客户端形态 | 独立 GUI 窗口 | 系统托盘常驻程序 |
| 管理后台 | 无 | 内置 Admin 单页应用 |
| 离线保护 | 无 | 离线宽限期 + 本地审计缓存 |
| 审批流程 | 无 | 外发申请 → 审批 → 水印导出 |

## 生产部署建议

### 服务端

- 使用 `gunicorn` + `uvicorn` workers 提升并发
- 前面加 Nginx 反向代理，配置 HTTPS + 速率限制
- 替换 SQLite 为 PostgreSQL（修改 `server/main.py` 中的 `db()` 函数）
- 添加 JWT 认证中间件保护 API
- 配置日志轮转和监控告警

### Agent

- 注册为 Windows 服务（使用 `nssm` 或 `pywin32` 服务框架）
- 配置系统代理指向 `127.0.0.1:3128`（可通过组策略统一下发）
- 将受控目录设置为网络共享路径 + 本地缓存
- 启用进程数字签名校验（`signature_check: true`）
- 设置强密码保护本地密钥缓存（`local_password`）

### 安全加固

- 定期轮换 KMS 主密钥
- 启用 Windows BitLocker 全盘加密
- 配置 Windows 事件日志转发到 SIEM
- 对 `agent_state/` 目录设置 ACL 仅允许 SYSTEM 和 Administrators 读取
- 真正的透明加密仍需 Windows Minifilter 驱动，本系统为 Python 用户态尽最大努力实现

## 故障排查

### 服务端无法启动

```bash
# 检查端口占用
netstat -ano | findstr :8000

# 检查 Python 版本（需 ≥ 3.10）
python --version

# 检查依赖是否完整安装
pip list | findstr "fastapi uvicorn"
```

### Agent 注册失败

```bash
# 确认服务端已启动并可访问
curl http://127.0.0.1:8000/health

# 检查 ITDLP_SERVER 环境变量
echo %ITDLP_SERVER%

# 查看离线审计日志
type agent_state\offline_audit.log
```

### 剪贴板守卫不工作

- 确认操作系统为 Windows（非 Linux/macOS）
- 确认 `pywin32` 已安装：`pip show pywin32`
- 检查托盘图标是否正常显示（蓝色 DLP 图标）

### 文件监控不触发

- 确认监控目录存在且有写入权限
- 确认文件扩展名在受控列表中
- 检查 watchdog 日志输出

### 清理数据

```bash
# 删除服务端数据库（重置所有数据）
del data\server.db

# 删除 Agent 状态
rmdir /s agent_state
```

## 开发指南

### 项目结构

```
new/
├── agent/                  # 终端 Agent
│   ├── __init__.py
│   ├── core.py            # Agent 核心逻辑
│   ├── tray_app.py        # 系统托盘主程序
│   ├── watcher.py         # 文件监控自动加密
│   ├── clipboard_guard.py # 剪贴板守卫
│   ├── usb_guard.py       # USB 守卫
│   ├── net_guard.py       # 网络代理守卫
│   └── process_verify.py  # 进程完整性校验
├── server/                 # 管理控制中心
│   ├── __init__.py
│   ├── main.py            # FastAPI 服务端
│   └── admin.html         # 管理后台 SPA
├── common/                 # 公共模块
│   ├── __init__.py
│   ├── crypto_utils.py    # 加密工具
│   └── watermark.py       # 数字水印
├── data/                   # 服务端数据（自动生成）
│   └── server.db          # SQLite 数据库
├── agent_state/            # Agent 状态（自动生成）
│   ├── agent_config.json
│   ├── policy_cache.json
│   └── key_cache_v2.json
├── demo.py                 # 一键演示脚本
├── requirements.txt        # 依赖清单
└── README.md              # 本文件
```

### 添加新的通道管控模块

1. 在 `agent/` 下创建新模块（如 `printer_guard.py`）
2. 实现 `start()` / `stop()` 接口
3. 在 `agent/tray_app.py` 的 `TrayApp.start()` 中集成

### 扩展受控文件类型

修改 `server/main.py` 中 `DEFAULT_POLICY["controlled_extensions"]` 列表。

### 自定义水印样式

修改 `common/watermark.py` 中的位置、颜色、透明度等参数。

## 许可证

仅供学习研究与企业内部技术验证使用。未经授权不得用于商业用途。
