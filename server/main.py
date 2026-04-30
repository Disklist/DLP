"""
IT 终端设备数据加密防泄漏系统 - 服务端管理控制中心（增强版）

改进点：
- 增加管理后台 /admin 单页应用
- 外发审批通过后自动添加数字水印
- 增强终端在线状态追踪
- 增加管理员专用 API

运行方式：
    uvicorn server.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

sys_path_inserted = False
try:
    from common.crypto_utils import decode_key, encode_key, generate_data_key, decrypt_file_to_bytes, unpack_encrypted_file, secure_delete
    from common.watermark import apply_watermark
except ImportError:
    import sys
    BASE_DIR = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(BASE_DIR))
    from common.crypto_utils import decode_key, encode_key, generate_data_key, decrypt_file_to_bytes, unpack_encrypted_file, secure_delete
    from common.watermark import apply_watermark
    sys_path_inserted = True

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "server.db"
ADMIN_HTML_PATH = Path(__file__).resolve().parent / "admin.html"

app = FastAPI(
    title="IT 终端设备数据加密防泄漏系统 - 管理控制中心",
    description="用于策略下发、KMS 托管、审计日志、外发审批与管理后台。",
    version="2.0.0",
)


DEFAULT_POLICY: Dict[str, Any] = {
    "policy_id": "POLICY-DEFAULT-001",
    "version": 3,
    "offline_grace_hours": 72,
    "controlled_extensions": [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".dwg", ".pdf", ".txt", ".png", ".jpg", ".csv"],
    "process_whitelist": ["winword.exe", "excel.exe", "powerpnt.exe", "acad.exe", "agent_demo.exe", "python.exe", "notepad.exe"],
    "clipboard_forbidden_targets": ["wechat.exe", "qq.exe", "telegram.exe", "browser.exe", "chrome.exe", "msedge.exe"],
    "usb_mode": "readonly",
    "network_upload_control": True,
    "watermark_enabled": True,
    "transparent_open_fallback_seconds": 30,
    "print_control": "audit_and_approve",
    "signature_check": False,
}


def current_ts() -> int:
    return int(time.time())


class TerminalRegisterRequest(BaseModel):
    terminal_id: str = Field(..., description="终端唯一编号")
    hostname: str
    user_id: str
    department: str = "default"


class KeyCreateRequest(BaseModel):
    terminal_id: str
    owner_id: str
    classification: str = "internal"


class KeyGrantRequest(BaseModel):
    key_id: str
    terminal_id: str
    process_name: str
    user_id: str
    purpose: str = "open"


class AuditLogRequest(BaseModel):
    terminal_id: str
    user_id: str
    action: str
    file_path: Optional[str] = None
    result: str = "success"
    detail: Dict[str, Any] = Field(default_factory=dict)


class ExportRequest(BaseModel):
    terminal_id: str
    user_id: str
    file_name: str
    reason: str
    key_id: str


class ApprovalRequest(BaseModel):
    approver_id: str
    approved: bool
    comment: str = ""


class PolicyUpdateRequest(BaseModel):
    policy: Dict[str, Any]
    operator_id: str = "admin"


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS terminals (
                terminal_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                user_id TEXT NOT NULL,
                department TEXT NOT NULL,
                registered_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                key_material TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                terminal_id TEXT NOT NULL,
                classification TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                terminal_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                file_path TEXT,
                result TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS export_requests (
                request_id TEXT PRIMARY KEY,
                terminal_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                reason TEXT NOT NULL,
                key_id TEXT NOT NULL,
                status TEXT NOT NULL,
                approver_id TEXT,
                comment TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                policy_json TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS terminal_watch_dirs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                terminal_id TEXT NOT NULL,
                directory TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (terminal_id) REFERENCES terminals(terminal_id) ON DELETE CASCADE
            );
            """
        )
        row = conn.execute("SELECT policy_id FROM policies WHERE policy_id=?", (DEFAULT_POLICY["policy_id"],)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO policies(policy_id, policy_json, version, updated_at) VALUES(?,?,?,?)",
                (
                    DEFAULT_POLICY["policy_id"],
                    json.dumps(DEFAULT_POLICY, ensure_ascii=False),
                    int(DEFAULT_POLICY["version"]),
                    current_ts(),
                ),
            )


def get_current_policy() -> Dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT policy_json FROM policies WHERE policy_id=?", (DEFAULT_POLICY["policy_id"],)).fetchone()
    if not row:
        return dict(DEFAULT_POLICY)
    return json.loads(row["policy_json"])


def save_current_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    policy = dict(policy)
    policy.setdefault("policy_id", DEFAULT_POLICY["policy_id"])
    policy["version"] = int(policy.get("version", DEFAULT_POLICY["version"])) + 1
    with db() as conn:
        conn.execute(
            """
            INSERT INTO policies(policy_id, policy_json, version, updated_at)
            VALUES(?,?,?,?)
            ON CONFLICT(policy_id) DO UPDATE SET
                policy_json=excluded.policy_json,
                version=excluded.version,
                updated_at=excluded.updated_at
            """,
            (
                policy["policy_id"],
                json.dumps(policy, ensure_ascii=False),
                int(policy["version"]),
                current_ts(),
            ),
        )
    return policy


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "it-dlp-management-center", "version": "2.0.0", "timestamp": int(time.time())}


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard() -> str:
    if ADMIN_HTML_PATH.exists():
        return ADMIN_HTML_PATH.read_text(encoding="utf-8")
    return "<h1>Admin UI not found</h1>"


@app.get("/api/admin/terminals")
def list_terminals() -> List[Dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM terminals ORDER BY last_seen_at DESC").fetchall()
    return [dict(row) for row in rows]


@app.delete("/api/admin/terminals/{terminal_id}")
def delete_terminal(terminal_id: str) -> Dict[str, Any]:
    with db() as conn:
        term = conn.execute("SELECT * FROM terminals WHERE terminal_id=?", (terminal_id,)).fetchone()
    if not term:
        raise HTTPException(status_code=404, detail="terminal not found")

    # 1. 获取该终端所有监控目录，递归解密其中 .itdlp 文件
    with db() as conn:
        dir_rows = conn.execute(
            "SELECT directory FROM terminal_watch_dirs WHERE terminal_id=?", (terminal_id,)
        ).fetchall()

    decrypted_count = 0
    failed_count = 0
    for row in dir_rows:
        root = Path(row["directory"])
        if not root.is_dir():
            continue
        for file_path in root.rglob("*.itdlp"):
            try:
                _decrypt_and_remove(str(file_path))
                decrypted_count += 1
            except Exception as exc:
                failed_count += 1
                print(f"[DeleteTerminal] 解密失败 {file_path}: {exc}")

    # 2. 清理该终端关联数据
    with db() as conn:
        conn.execute("DELETE FROM terminal_watch_dirs WHERE terminal_id=?", (terminal_id,))
        conn.execute("DELETE FROM audit_logs WHERE terminal_id=?", (terminal_id,))
        conn.execute("DELETE FROM export_requests WHERE terminal_id=?", (terminal_id,))
        conn.execute("DELETE FROM keys WHERE terminal_id=?", (terminal_id,))
        conn.execute("DELETE FROM terminals WHERE terminal_id=?", (terminal_id,))

    return {
        "deleted": True,
        "terminal_id": terminal_id,
        "decrypted_files": decrypted_count,
        "failed": failed_count,
    }


def _decrypt_and_remove(encrypted_path: str) -> None:
    """服务端解密单个 .itdlp 文件到原始文件名，然后删除该 .itdlp。"""
    payload = unpack_encrypted_file(Path(encrypted_path).read_bytes())
    key_id = payload.header["key_id"]

    with db() as conn:
        key_row = conn.execute(
            "SELECT key_material FROM keys WHERE key_id=? AND status='active'", (key_id,)
        ).fetchone()
    if not key_row:
        raise RuntimeError(f"Key {key_id} not found or inactive")

    key_bytes = decode_key(key_row["key_material"])
    original_name = payload.header.get("original_name", "")
    if not original_name:
        original_name = Path(encrypted_path).stem
    output = str(Path(encrypted_path).with_name(original_name))
    # 如果输出已存在，加后缀
    if Path(output).exists():
        stem = Path(original_name).stem
        suffix = Path(original_name).suffix
        for i in range(1, 100):
            output = str(Path(encrypted_path).with_name(f"{stem}_{i}{suffix}"))
            if not Path(output).exists():
                break

    _, plaintext = decrypt_file_to_bytes(encrypted_path, key_bytes)
    with open(output, "wb") as f:
        f.write(plaintext)
    secure_delete(encrypted_path)


@app.get("/api/admin/export-requests")
def list_all_export_requests(status: Optional[str] = None) -> List[Dict[str, Any]]:
    with db() as conn:
        if status:
            rows = conn.execute("SELECT * FROM export_requests WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM export_requests ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/admin/policy")
def admin_get_policy() -> Dict[str, Any]:
    return get_current_policy()


@app.put("/api/admin/policy")
def admin_update_policy(req: PolicyUpdateRequest) -> Dict[str, Any]:
    policy = save_current_policy(req.policy)
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_logs(terminal_id, user_id, action, file_path, result, detail, created_at) VALUES(?,?,?,?,?,?,?)",
            (
                "SERVER",
                req.operator_id,
                "policy_update",
                None,
                "success",
                json.dumps({"policy_id": policy.get("policy_id"), "version": policy.get("version")}, ensure_ascii=False),
                current_ts(),
            ),
        )
    return policy


@app.get("/api/admin/stats")
def admin_stats() -> Dict[str, Any]:
    with db() as conn:
        terminals = conn.execute("SELECT COUNT(*) AS c FROM terminals").fetchone()["c"]
        logs = conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]
        pending = conn.execute("SELECT COUNT(*) AS c FROM export_requests WHERE status='pending'").fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) AS c FROM audit_logs WHERE result='blocked'").fetchone()["c"]
    return {"terminals": terminals, "audit_logs": logs, "pending_exports": pending, "blocked_events": blocked}


# ---------------------------------------------------------------------------
# Terminal & Policy
# ---------------------------------------------------------------------------

@app.post("/api/terminals/register")
def register_terminal(req: TerminalRegisterRequest) -> Dict[str, Any]:
    now = current_ts()
    with db() as conn:
        # 1. 注册或更新终端基本信息
        conn.execute(
            """
            INSERT INTO terminals(terminal_id, hostname, user_id, department, registered_at, last_seen_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(terminal_id) DO UPDATE SET
                hostname=excluded.hostname,
                user_id=excluded.user_id,
                department=excluded.department,
                last_seen_at=excluded.last_seen_at
            """,
            (req.terminal_id, req.hostname, req.user_id, req.department, now, now),
        )
        
        # 2. 自动添加默认监控目录
        # 检查该终端是否已经有监控目录，如果没有，则添加系统默认路径
        existing = conn.execute(
            "SELECT id FROM terminal_watch_dirs WHERE terminal_id=?", (req.terminal_id,)
        ).fetchone()
        
        if not existing:
            # 根据系统规范，为该用户构造默认的 Windows 受控资料路径
            default_path = f"C:\\Users\\{req.user_id}\\Documents\\受控资料"
            conn.execute(
                "INSERT INTO terminal_watch_dirs(terminal_id, directory, created_at) VALUES(?,?,?)",
                (req.terminal_id, default_path, now),
            )
            
    return {"registered": True, "terminal_id": req.terminal_id, "policy": get_current_policy()}


@app.get("/api/policies/{terminal_id}")
def get_policy(terminal_id: str) -> Dict[str, Any]:
    with db() as conn:
        terminal = conn.execute("SELECT * FROM terminals WHERE terminal_id=?", (terminal_id,)).fetchone()
    if not terminal:
        raise HTTPException(status_code=404, detail="terminal not registered")
    # 更新最后在线时间
    with db() as conn:
        conn.execute("UPDATE terminals SET last_seen_at=? WHERE terminal_id=?", (current_ts(), terminal_id))
    policy = get_current_policy()
    # 附带该终端的监控目录
    with db() as conn:
        rows = conn.execute(
            "SELECT id, directory FROM terminal_watch_dirs WHERE terminal_id=? ORDER BY id", (terminal_id,)
        ).fetchall()
    policy["watch_directories"] = [row["directory"] for row in rows]
    return policy


# ---------------------------------------------------------------------------
# Terminal Watch Directories (Admin)
# ---------------------------------------------------------------------------

class WatchDirRequest(BaseModel):
    directory: str = Field(..., description="要添加的监控目录绝对路径")


class WatchDirResponse(BaseModel):
    id: int
    terminal_id: str
    directory: str
    created_at: int


@app.get("/api/admin/terminals/{terminal_id}/watch-dirs")
def list_watch_dirs(terminal_id: str) -> List[Dict[str, Any]]:
    with db() as conn:
        term = conn.execute("SELECT terminal_id FROM terminals WHERE terminal_id=?", (terminal_id,)).fetchone()
    if not term:
        raise HTTPException(status_code=404, detail="terminal not found")
    with db() as conn:
        rows = conn.execute(
            "SELECT id, terminal_id, directory, created_at FROM terminal_watch_dirs WHERE terminal_id=? ORDER BY id",
            (terminal_id,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/terminals/{terminal_id}/watch-dirs")
def add_watch_dir(terminal_id: str, req: WatchDirRequest) -> Dict[str, Any]:
    with db() as conn:
        term = conn.execute("SELECT terminal_id FROM terminals WHERE terminal_id=?", (terminal_id,)).fetchone()
    if not term:
        raise HTTPException(status_code=404, detail="terminal not found")

    directory = req.directory.strip()
    if not directory:
        raise HTTPException(status_code=400, detail="目录路径不能为空")
    # 校验路径格式（必须是绝对路径）
    dir_path = Path(directory)
    if not dir_path.is_absolute():
        raise HTTPException(status_code=400, detail="必须提供绝对路径，例如 C:\\Users\\xxx\\Documents\\受控资料")
    # 校验目录是否存在
    if not dir_path.exists():
        raise HTTPException(status_code=400, detail=f"目录不存在: {directory}")
    if not dir_path.is_dir():
        raise HTTPException(status_code=400, detail=f"路径不是目录: {directory}")

    # 检查是否已存在
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM terminal_watch_dirs WHERE terminal_id=? AND directory=?",
            (terminal_id, directory),
        ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="该目录已添加")

    now = current_ts()
    with db() as conn:
        conn.execute(
            "INSERT INTO terminal_watch_dirs(terminal_id, directory, created_at) VALUES(?,?,?)",
            (terminal_id, directory, now),
        )
    return {"added": True, "terminal_id": terminal_id, "directory": directory}


@app.delete("/api/admin/terminals/{terminal_id}/watch-dirs/{dir_id}")
def remove_watch_dir(terminal_id: str, dir_id: int) -> Dict[str, Any]:
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM terminal_watch_dirs WHERE id=? AND terminal_id=?",
            (dir_id, terminal_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="watch directory entry not found")
    with db() as conn:
        conn.execute("DELETE FROM terminal_watch_dirs WHERE id=?", (dir_id,))
    return {"removed": True, "id": dir_id}


# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------

@app.post("/api/kms/keys")
def create_data_key(req: KeyCreateRequest) -> Dict[str, str]:
    key_id = "KEY-" + uuid.uuid4().hex.upper()
    key_material = encode_key(generate_data_key())
    now = current_ts()
    with db() as conn:
        conn.execute(
            "INSERT INTO keys(key_id, key_material, owner_id, terminal_id, classification, created_at, status) VALUES(?,?,?,?,?,?,?)",
            (key_id, key_material, req.owner_id, req.terminal_id, req.classification, now, "active"),
        )
    return {"key_id": key_id, "algorithm": "AES-256-GCM", "classification": req.classification}


@app.post("/api/kms/grant")
def grant_key(req: KeyGrantRequest) -> Dict[str, str]:
    policy = get_current_policy()
    if req.process_name.lower() not in [p.lower() for p in policy["process_whitelist"]]:
        raise HTTPException(status_code=403, detail="process is not authorized to decrypt controlled files")

    with db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key_id=? AND status='active'", (req.key_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="key not found or inactive")

    return {
        "key_id": req.key_id,
        "key_material": row["key_material"],
        "algorithm": "AES-256-GCM",
        "grant_scope": req.purpose,
    }


@app.get("/api/admin/keys")
def list_keys() -> List[Dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/keys/{key_id}/revoke")
def revoke_key(key_id: str) -> Dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key_id=?", (key_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="key not found")
        conn.execute("UPDATE keys SET status='revoked' WHERE key_id=?", (key_id,))
    return {"key_id": key_id, "status": "revoked"}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@app.post("/api/audit/logs")
def submit_audit_log(req: AuditLogRequest) -> Dict[str, Any]:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_logs(terminal_id, user_id, action, file_path, result, detail, created_at) VALUES(?,?,?,?,?,?,?)",
            (req.terminal_id, req.user_id, req.action, req.file_path, req.result, json.dumps(req.detail, ensure_ascii=False), current_ts()),
        )
    return {"accepted": True}


@app.get("/api/audit/logs")
def list_audit_logs(
    limit: int = 100,
    terminal_id: Optional[str] = None,
    action: Optional[str] = None,
    result: Optional[str] = None,
) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    where = []
    params: list[Any] = []
    if terminal_id:
        where.append("terminal_id=?")
        params.append(terminal_id)
    if action:
        where.append("action=?")
        params.append(action)
    if result:
        where.append("result=?")
        params.append(result)
    sql = "SELECT * FROM audit_logs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Export Approval with Watermark
# ---------------------------------------------------------------------------

@app.post("/api/export/requests")
def create_export_request(req: ExportRequest) -> Dict[str, Any]:
    request_id = "REQ-" + uuid.uuid4().hex.upper()
    now = current_ts()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO export_requests(request_id, terminal_id, user_id, file_name, reason, key_id, status, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (request_id, req.terminal_id, req.user_id, req.file_name, req.reason, req.key_id, "pending", now, now),
        )
    return {"request_id": request_id, "status": "pending"}


@app.post("/api/export/requests/{request_id}/approve")
def approve_export_request(request_id: str, req: ApprovalRequest) -> Dict[str, Any]:
    status = "approved" if req.approved else "rejected"
    with db() as conn:
        row = conn.execute("SELECT * FROM export_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="request not found")
        conn.execute(
            "UPDATE export_requests SET status=?, approver_id=?, comment=?, updated_at=? WHERE request_id=?",
            (status, req.approver_id, req.comment, current_ts(), request_id),
        )

    # 若通过且启用水印，生成带水印的旁路文件
    watermark_path: Optional[str] = None
    if req.approved and get_current_policy().get("watermark_enabled"):
        try:
            safe_name = "".join(c for c in row["file_name"] if c.isalnum() or c in "._-")
            export_dir = DATA_DIR / "exports"
            export_dir.mkdir(exist_ok=True)
            src = export_dir / f"{request_id}_{safe_name}"
            # 实际场景中，这里应从服务端保存的密文解密后再打水印
            # 演示阶段：若文件存在则打水印，否则创建标记文件
            if src.exists():
                out = str(src.with_suffix(".watermarked" + Path(safe_name).suffix))
                apply_watermark(str(src), out, user_id=row["user_id"], extra=f"Approved by {req.approver_id}")
                watermark_path = out
            else:
                # 创建一个带水印的标记文件供下载
                out = export_dir / f"{request_id}_{safe_name}.watermarked.txt"
                from common.watermark import add_text_watermark
                dummy = export_dir / f"{request_id}_dummy.txt"
                dummy.write_text("[Exported Content Placeholder]\n", encoding="utf-8")
                add_text_watermark(str(dummy), str(out), user_id=row["user_id"], extra=f"Approved by {req.approver_id}")
                dummy.unlink(missing_ok=True)
                watermark_path = str(out)
        except Exception as exc:
            print(f"Watermark generation failed: {exc}")

    result: Dict[str, Any] = {"request_id": request_id, "status": status}
    if watermark_path:
        result["watermark_file"] = watermark_path
    return result


@app.get("/api/export/requests/{request_id}")
def get_export_request(request_id: str) -> Dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM export_requests WHERE request_id=?", (request_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="request not found")
    return dict(row)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
