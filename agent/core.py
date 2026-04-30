"""
IT 终端设备数据加密防泄漏系统 - 终端 Agent 核心（增强版）

改进点：
- 安全临时文件解密 + 进程退出后安全擦除
- 本地密钥 Argon2 保护
- 进程完整性校验（路径 + 可选签名）
- 增强离线策略与宽限期处理
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
import uuid
import ctypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.crypto_utils import (
    SecureTempFile,
    decode_key,
    decrypt_file,
    encrypt_file,
    generate_data_key,
    secure_delete,
    secure_zero,
    protect_local_key,
    unpack_encrypted_file,
    unprotect_local_key,
)
from agent.process_verify import verify_executable_authorized, verify_process_authorized

if sys.platform == "win32":
    from ctypes import wintypes

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = BASE_DIR / "agent_state"
STATE_DIR.mkdir(exist_ok=True)
CONFIG_PATH = STATE_DIR / "agent_config.json"
POLICY_CACHE_PATH = STATE_DIR / "policy_cache.json"
KEY_CACHE_PATH = STATE_DIR / "key_cache_v2.json"
LOCAL_SECRET_PATH = STATE_DIR / "local_secret.key"
DEFAULT_SERVER = os.getenv("ITDLP_SERVER", "http://127.0.0.1:8000")


@dataclass
class AgentConfig:
    server_url: str
    terminal_id: str
    user_id: str
    department: str
    hostname: str
    local_password: str = ""  # 用于本地密钥保护


class EndpointAgent:
    """终端 Agent 主类（增强版）。"""

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        self.config = config or self.load_or_create_config()

    def load_or_create_config(self) -> AgentConfig:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            cfg = AgentConfig(**data)
            changed = False
            env_server = os.getenv("ITDLP_SERVER")
            if env_server and cfg.server_url != env_server.rstrip("/"):
                cfg.server_url = env_server.rstrip("/")
                changed = True
            env_password = os.getenv("ITDLP_LOCAL_PASSWORD")
            if env_password and cfg.local_password != env_password:
                cfg.local_password = env_password
                changed = True
            if changed:
                CONFIG_PATH.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")
            return cfg
        hostname = socket.gethostname()
        cfg = AgentConfig(
            server_url=DEFAULT_SERVER.rstrip("/"),
            terminal_id=f"TERM-{hostname.upper()}-{uuid.uuid4().hex[:6].upper()}",
            user_id=os.getenv("USER", os.getenv("USERNAME", "demo_user")),
            department="研发中心",
            hostname=hostname,
            local_password=os.getenv("ITDLP_LOCAL_PASSWORD", ""),
        )
        CONFIG_PATH.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")
        return cfg

    def save_config(self) -> None:
        CONFIG_PATH.write_text(json.dumps(asdict(self.config), ensure_ascii=False, indent=2), encoding="utf-8")

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = self.config.server_url + path
        kwargs.setdefault("timeout", 8)
        return requests.request(method, url, **kwargs)

    def local_key_password(self) -> str:
        """
        返回本地密钥缓存保护口令。

        优先使用环境变量/配置中的显式口令；否则生成一个仅本机保存的随机 secret。
        这不是内核级保护，但比固定默认口令更适合真实桌面部署。
        """
        env_password = os.getenv("ITDLP_LOCAL_PASSWORD")
        if env_password:
            return env_password
        if self.config.local_password:
            return self.config.local_password
        if LOCAL_SECRET_PATH.exists():
            return LOCAL_SECRET_PATH.read_text(encoding="utf-8").strip()
        secret = secrets.token_urlsafe(32)
        LOCAL_SECRET_PATH.write_text(secret, encoding="utf-8")
        try:
            os.chmod(LOCAL_SECRET_PATH, 0o600)
        except Exception:
            pass
        return secret

    def register(self) -> Dict[str, Any]:
        payload = {
            "terminal_id": self.config.terminal_id,
            "hostname": self.config.hostname,
            "user_id": self.config.user_id,
            "department": self.config.department,
        }
        resp = self.request("POST", "/api/terminals/register", json=payload)
        resp.raise_for_status()
        data = resp.json()
        policy = data["policy"]
        policy["cached_at"] = int(time.time())
        POLICY_CACHE_PATH.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
        self.audit("register", None, "success", {"platform": platform.platform()})
        return data

    def sync_policy(self) -> Dict[str, Any]:
        try:
            resp = self.request("GET", f"/api/policies/{self.config.terminal_id}")
            resp.raise_for_status()
            policy = resp.json()
            policy["cached_at"] = int(time.time())
            POLICY_CACHE_PATH.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
            self.audit("policy_sync", None, "success", {"policy_id": policy.get("policy_id"), "version": policy.get("version")})
            return policy
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return self.register()["policy"]
            if POLICY_CACHE_PATH.exists():
                policy = json.loads(POLICY_CACHE_PATH.read_text(encoding="utf-8"))
                cached_at = int(policy.get("cached_at", 0))
                grace = int(policy.get("offline_grace_hours", 0)) * 3600
                if time.time() - cached_at <= grace:
                    return policy
                raise RuntimeError("离线授权已超时，受控文件自动锁定") from exc
            raise
        except Exception as exc:
            if POLICY_CACHE_PATH.exists():
                policy = json.loads(POLICY_CACHE_PATH.read_text(encoding="utf-8"))
                cached_at = int(policy.get("cached_at", 0))
                grace = int(policy.get("offline_grace_hours", 0)) * 3600
                if time.time() - cached_at <= grace:
                    return policy
                raise RuntimeError("离线授权已超时，受控文件自动锁定") from exc
            raise

    def audit(self, action: str, file_path: Optional[str], result: str, detail: Dict[str, Any]) -> None:
        payload = {
            "terminal_id": self.config.terminal_id,
            "user_id": self.config.user_id,
            "action": action,
            "file_path": file_path,
            "result": result,
            "detail": detail,
        }
        try:
            self.request("POST", "/api/audit/logs", json=payload).raise_for_status()
        except Exception:
            offline_log = STATE_DIR / "offline_audit.log"
            with offline_log.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps({**payload, "created_at": int(time.time())}, ensure_ascii=False) + "\n")

    def load_policy(self) -> Dict[str, Any]:
        if not POLICY_CACHE_PATH.exists():
            return self.sync_policy()
        return json.loads(POLICY_CACHE_PATH.read_text(encoding="utf-8"))

    def is_controlled_file(self, path: str) -> bool:
        policy = self.load_policy()
        suffix = Path(path).suffix.lower()
        if suffix == ".itdlp":
            return True
        return suffix in [ext.lower() for ext in policy.get("controlled_extensions", [])]

    def create_server_key(self, classification: str = "internal") -> str:
        payload = {
            "terminal_id": self.config.terminal_id,
            "owner_id": self.config.user_id,
            "classification": classification,
        }
        resp = self.request("POST", "/api/kms/keys", json=payload)
        resp.raise_for_status()
        return resp.json()["key_id"]

    def grant_key(self, key_id: str, process_name: str, purpose: str = "open", caller_pid: Optional[int] = None) -> bytes:
        payload = {
            "key_id": key_id,
            "terminal_id": self.config.terminal_id,
            "process_name": process_name,
            "user_id": self.config.user_id,
            "purpose": purpose,
        }
        resp = self.request("POST", "/api/kms/grant", json=payload)
        resp.raise_for_status()
        key_material = resp.json()["key_material"]
        key_bytes = decode_key(key_material)

        # 本地缓存（Argon2 保护）
        cache = {}
        if KEY_CACHE_PATH.exists():
            try:
                cache = json.loads(KEY_CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                cache = {}
        pwd = self.local_key_password()
        cache[key_id] = protect_local_key(key_bytes, password=pwd)
        KEY_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(KEY_CACHE_PATH, 0o600)
        except Exception:
            pass
        return key_bytes

    def _load_cached_key(self, key_id: str) -> Optional[bytes]:
        if not KEY_CACHE_PATH.exists():
            return None
        try:
            cache = json.loads(KEY_CACHE_PATH.read_text(encoding="utf-8"))
            protected = cache.get(key_id)
            if not protected:
                return None
            pwd = self.local_key_password()
            return unprotect_local_key(protected, password=pwd)
        except Exception:
            return None

    def protect_file(self, path: str, classification: str = "internal") -> str:
        source = Path(path)
        if source.suffix.lower() == ".itdlp":
            raise RuntimeError("该文件已经是 IT-DLP 密文，禁止重复加密")
        if not source.exists() or not source.is_file():
            raise RuntimeError("待加密文件不存在或不是普通文件")
        if not self.is_controlled_file(path):
            raise RuntimeError("该文件类型不在受控范围内")
        key_id = self.create_server_key(classification=classification)
        key = self.grant_key(key_id, "python.exe", purpose="encrypt")
        key_buffer = bytearray(key)
        output = str(source.with_name(source.name + ".itdlp"))
        header = {
            "format": "ITDLP-Encrypted-File",
            "algorithm": "AES-256-GCM",
            "key_id": key_id,
            "owner_id": self.config.user_id,
            "terminal_id": self.config.terminal_id,
            "classification": classification,
            "original_name": source.name,
            "created_at": str(int(time.time())),
        }
        try:
            encrypt_file(str(source), output, bytes(key_buffer), header)
            secure_delete(str(source))
        finally:
            secure_zero(key_buffer)
        self.audit("file_encrypt", output, "success", {"key_id": key_id, "classification": classification})
        return output

    def open_file_secure(self, encrypted_path: str, process_name: str, caller_pid: Optional[int] = None) -> None:
        """
        安全打开加密文件：解密到安全临时文件，启动授权进程，进程退出后安全擦除。
        若用户编辑了临时文件，自动重新加密保存回原 .itdlp 文件。
        """
        payload = unpack_encrypted_file(Path(encrypted_path).read_bytes())
        key_id = payload.header["key_id"]

        # 进程校验
        policy = self.load_policy()
        whitelist = policy.get("process_whitelist", [])
        if caller_pid is not None:
            ok, reason = verify_process_authorized(
                caller_pid, whitelist, check_signature=policy.get("signature_check", False)
            )
            if not ok:
                self.audit("file_decrypt", encrypted_path, "blocked", {"reason": reason})
                raise RuntimeError(f"进程未授权: {reason}")
        else:
            ok, reason, resolved_path = verify_executable_authorized(
                process_name, whitelist, check_signature=policy.get("signature_check", False)
            )
            if not ok:
                self.audit("file_decrypt", encrypted_path, "blocked", {"reason": reason, "process_name": process_name})
                raise RuntimeError(f"进程未授权: {reason}")
            process_name = resolved_path or process_name

        # 优先用缓存密钥
        key = self._load_cached_key(key_id)
        if key is None:
            key = self.grant_key(key_id, Path(process_name).name, purpose="open", caller_pid=caller_pid)
        key_buffer = bytearray(key)

        original = payload.header.get("original_name", "decrypted_output.bin")
        suffix = Path(original).suffix

        with SecureTempFile(suffix=suffix) as tmp_path:
            try:
                decrypt_file(encrypted_path, tmp_path, bytes(key_buffer))
                mtime_before = os.path.getmtime(tmp_path)
                self.audit("file_decrypt", encrypted_path, "success", {"process_name": process_name, "tmp": tmp_path})
                _write_vsto_session(tmp_path, key_buffer, payload.header)
                proc = subprocess.Popen([process_name, tmp_path], shell=False)
                try:
                    proc.wait()
                except KeyboardInterrupt:
                    proc.terminate()
                    proc.wait()
                finally:
                    _clear_vsto_session()
                # 检测用户是否编辑了文件，如有修改则重新加密保存
                try:
                    if os.path.getmtime(tmp_path) > mtime_before:
                        header = dict(payload.header)
                        header.pop("nonce", None)
                        header["updated_at"] = str(int(time.time()))
                        encrypt_file(tmp_path, encrypted_path, bytes(key_buffer), header)
                        self.audit("file_reencrypt", encrypted_path, "success", {"process_name": process_name})
                except FileNotFoundError:
                    pass
            finally:
                secure_zero(key_buffer)

    def open_file_transparent(self, encrypted_path: str) -> None:
        """
        双击 .itdlp 的透明打开入口。

        Agent 使用本机缓存或 KMS 授权解密到随机临时文件，临时文件保留原扩展名，
        再交给 Windows 默认应用打开；应用关闭后自动安全擦除临时明文。
        若用户编辑了文件，自动重新加密保存回原 .itdlp。
        """
        encrypted = Path(encrypted_path)
        if encrypted.suffix.lower() != ".itdlp":
            raise RuntimeError("只能透明打开 .itdlp 加密文件")
        if not encrypted.exists():
            raise RuntimeError("文件不存在")

        payload = unpack_encrypted_file(encrypted.read_bytes())
        key_id = payload.header["key_id"]
        key = self._load_cached_key(key_id)
        if key is None:
            key = self.grant_key(key_id, "python.exe", purpose="transparent_open")
        key_buffer = bytearray(key)

        original = payload.header.get("original_name") or encrypted.with_suffix("").name
        suffix = Path(original).suffix or ".tmp"
        with SecureTempFile(suffix=suffix) as tmp_path:
            try:
                decrypt_file(str(encrypted), tmp_path, bytes(key_buffer))
                mtime_before = os.path.getmtime(tmp_path)
                self.audit(
                    "file_transparent_open",
                    str(encrypted),
                    "success",
                    {"tmp_suffix": suffix, "original_name": original},
                )
                _write_vsto_session(tmp_path, key_buffer, payload.header)
                try:
                    self._open_plain_file_and_wait(tmp_path)
                finally:
                    _clear_vsto_session()
                # 检测用户是否编辑了文件，如有修改则重新加密保存
                try:
                    if os.path.getmtime(tmp_path) > mtime_before:
                        header = dict(payload.header)
                        header.pop("nonce", None)
                        header["updated_at"] = str(int(time.time()))
                        encrypt_file(str(tmp_path), str(encrypted), bytes(key_buffer), header)
                        self.audit("file_reencrypt", str(encrypted), "success", {"original_name": original})
                except FileNotFoundError:
                    pass
            finally:
                secure_zero(key_buffer)

    def _open_plain_file_and_wait(self, path: str) -> None:
        if sys.platform == "win32":
            self._shell_execute_and_wait(path)
            return
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        proc = subprocess.Popen([opener, path], shell=False)
        proc.wait()

    def _shell_execute_and_wait(self, path: str) -> None:
        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SEE_MASK_NOASYNC = 0x00000100
        SW_SHOWNORMAL = 1
        WAIT_OBJECT_0 = 0
        INFINITE = 0xFFFFFFFF

        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", wintypes.LPVOID),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        info = SHELLEXECUTEINFO()
        info.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        info.hwnd = None
        info.lpVerb = "open"
        info.lpFile = path
        info.lpParameters = None
        info.lpDirectory = str(Path(path).parent)
        info.nShow = SW_SHOWNORMAL

        shell_execute_ex = ctypes.windll.shell32.ShellExecuteExW
        shell_execute_ex.argtypes = [ctypes.POINTER(SHELLEXECUTEINFO)]
        shell_execute_ex.restype = wintypes.BOOL
        if not shell_execute_ex(ctypes.byref(info)):
            raise ctypes.WinError()

        if info.hProcess:
            wait = ctypes.windll.kernel32.WaitForSingleObject
            wait.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            wait.restype = wintypes.DWORD
            close = ctypes.windll.kernel32.CloseHandle
            close.argtypes = [wintypes.HANDLE]
            close.restype = wintypes.BOOL
            try:
                result = wait(info.hProcess, INFINITE)
                if result != WAIT_OBJECT_0:
                    raise RuntimeError(f"等待打开进程结束失败: {result}")
            finally:
                close(info.hProcess)
        else:
            # ShellExecuteEx 未能获取进程句柄（常见于 UWP 应用或 DDE 委托场景），
            # 轮询检测文件是否仍被锁定：尝试以读写模式打开文件，成功即表示应用已释放。
            self._poll_file_released(path)

    def _poll_file_released(self, path: str, timeout: int = 3600) -> None:
        """轮询直到文件不再被其他进程锁定（应用已关闭释放文件）。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                fd = os.open(path, os.O_RDWR)
                os.close(fd)
                return
            except (OSError, IOError):
                time.sleep(0.5)
        # 超时后不再等待，由上层 SecureTempFile 安全擦除

    def decrypt_to_file_for_approval(self, encrypted_path: str, output_path: str) -> Dict[str, str]:
        """审批/测试场景使用：解密到指定文件，调用方负责后续水印和分发。"""
        payload = unpack_encrypted_file(Path(encrypted_path).read_bytes())
        key_id = payload.header["key_id"]
        key = self._load_cached_key(key_id)
        if key is None:
            key = self.grant_key(key_id, "python.exe", purpose="export")
        key_buffer = bytearray(key)
        try:
            header = decrypt_file(encrypted_path, output_path, bytes(key_buffer))
            self.audit("file_export_decrypt", encrypted_path, "success", {"output": output_path})
            return header
        finally:
            secure_zero(key_buffer)

    def decrypt_itdlp_in_place(self, encrypted_path: str) -> str:
        """解密单个 .itdlp 文件到同目录下的原始文件名，然后安全擦除该 .itdlp。"""
        payload = unpack_encrypted_file(Path(encrypted_path).read_bytes())
        key_id = payload.header["key_id"]
        key = self._load_cached_key(key_id)
        if key is None:
            key = self.grant_key(key_id, "python.exe", purpose="decrypt_dir")
        key_buffer = bytearray(key)
        try:
            original_name = payload.header.get("original_name", "")
            if not original_name:
                original_name = Path(encrypted_path).stem
            output = str(Path(encrypted_path).with_name(original_name))
            # 如果输出文件已存在，加上序号避免覆盖
            if Path(output).exists():
                stem = Path(original_name).stem
                suffix = Path(original_name).suffix
                for i in range(1, 100):
                    alt = f"{stem}_{i}{suffix}"
                    output = str(Path(encrypted_path).with_name(alt))
                    if not Path(output).exists():
                        break
            decrypt_file(encrypted_path, output, bytes(key_buffer))
            secure_delete(encrypted_path)
            self.audit("file_decrypt_in_place", encrypted_path, "success", {"output": output})
            return output
        finally:
            secure_zero(key_buffer)

    def clipboard_check(self, source_file: str, target_process: str, target_pid: Optional[int] = None) -> bool:
        policy = self.load_policy()
        forbidden = [p.lower() for p in policy.get("clipboard_forbidden_targets", [])]
        blocked = self.is_controlled_file(source_file) and target_process.lower() in forbidden
        self.audit(
            "clipboard_control",
            source_file,
            "blocked" if blocked else "allowed",
            {"target_process": target_process, "target_pid": target_pid},
        )
        return not blocked

    def screenshot_check(self, active_file: str) -> bool:
        blocked = self.is_controlled_file(active_file)
        self.audit("screenshot_control", active_file, "blocked" if blocked else "allowed", {"watermark": True})
        return not blocked

    def usb_check(self, operation: str, file_path: str) -> bool:
        policy = self.load_policy()
        mode = policy.get("usb_mode", "readonly")
        blocked = mode == "disabled" or (mode == "readonly" and operation.lower() in {"write", "copy_out"})
        self.audit("usb_control", file_path, "blocked" if blocked else "allowed", {"operation": operation, "mode": mode})
        return not blocked

    def network_upload_check(self, file_path: str, port: int) -> bool:
        policy = self.load_policy()
        blocked = bool(policy.get("network_upload_control")) and self.is_controlled_file(file_path) and port in {80, 443, 25}
        self.audit("network_upload_control", file_path, "blocked" if blocked else "allowed", {"port": port})
        return not blocked

    def create_export_request(self, encrypted_path: str, reason: str) -> Dict[str, Any]:
        payload = unpack_encrypted_file(Path(encrypted_path).read_bytes())
        body = {
            "terminal_id": self.config.terminal_id,
            "user_id": self.config.user_id,
            "file_name": payload.header.get("original_name", Path(encrypted_path).name),
            "reason": reason,
            "key_id": payload.header["key_id"],
        }
        resp = self.request("POST", "/api/export/requests", json=body)
        resp.raise_for_status()
        data = resp.json()
        self.audit("export_request", encrypted_path, "pending", {"request_id": data["request_id"], "reason": reason})
        return data


def _write_vsto_session(tmp_path: str, key_buffer: bytearray, header: dict) -> None:
    """写入 VSTO 会话文件，供 C# Word Add-in 读取加密密钥。

    文件位置: %TEMP%/itdlp_session.json
    """
    import json as _json
    from common.crypto_utils import encode_key

    session = {
        "temp_file_path": str(Path(tmp_path).resolve()),
        "key_base64": encode_key(bytes(key_buffer)),
        "header": {
            k: v for k, v in header.items()
            if k != "nonce"  # 不传给 VSTO（每次加密生成新 nonce）
        },
        "agent_pid": os.getpid(),
    }
    session_path = Path(os.environ.get("TEMP", "/tmp")) / "itdlp_session.json"
    try:
        session_path.write_text(_json.dumps(session, ensure_ascii=False), encoding="utf-8")
        print(f"[VSTO] 会话文件已写入: {session_path}")
    except Exception as exc:
        print(f"[VSTO] 写入会话文件失败: {exc}")


def _clear_vsto_session() -> None:
    """删除 VSTO 会话文件。"""
    session_path = Path(os.environ.get("TEMP", "/tmp")) / "itdlp_session.json"
    try:
        if session_path.exists():
            session_path.unlink()
            print("[VSTO] 会话文件已清理")
    except Exception as exc:
        print(f"[VSTO] 清理会话文件失败: {exc}")


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(description="IT 终端数据加密防泄漏 Agent 核心")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("register", help="注册终端并同步策略")
    sub.add_parser("sync-policy", help="同步服务端安全策略")

    p_protect = sub.add_parser("protect", help="加密受控文件")
    p_protect.add_argument("path")
    p_protect.add_argument("--classification", default="internal")

    p_open = sub.add_parser("open", help="使用授权进程打开加密文件（安全临时文件方式）")
    p_open.add_argument("path")
    p_open.add_argument("--process", default="notepad.exe")

    p_transparent = sub.add_parser("transparent-open", help="双击 .itdlp 使用：按原文件类型透明打开")
    p_transparent.add_argument("path")

    p_decrypt_to = sub.add_parser("decrypt-to", help="审批或测试用：解密到指定输出文件")
    p_decrypt_to.add_argument("path")
    p_decrypt_to.add_argument("output")

    sub.add_parser("install-association", help="注册 Windows .itdlp 双击打开关联")
    sub.add_parser("uninstall-association", help="卸载 Windows .itdlp 双击打开关联")

    p_copy = sub.add_parser("copy-check", help="剪贴板外发检查")
    p_copy.add_argument("--source", required=True)
    p_copy.add_argument("--target", required=True)

    p_screen = sub.add_parser("screenshot-check", help="截屏检查")
    p_screen.add_argument("--active-file", required=True)

    p_usb = sub.add_parser("usb-check", help="USB 外设管控")
    p_usb.add_argument("--operation", required=True)
    p_usb.add_argument("--file", required=True)

    p_net = sub.add_parser("upload-check", help="网络上传拦截")
    p_net.add_argument("--file", required=True)
    p_net.add_argument("--port", type=int, default=443)

    p_export = sub.add_parser("export-request", help="发起外发解密审批")
    p_export.add_argument("path")
    p_export.add_argument("--reason", required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    agent = EndpointAgent()

    if args.command == "register":
        print(json.dumps(agent.register(), ensure_ascii=False, indent=2))
    elif args.command == "sync-policy":
        print(json.dumps(agent.sync_policy(), ensure_ascii=False, indent=2))
    elif args.command == "protect":
        print(agent.protect_file(args.path, classification=args.classification))
    elif args.command == "open":
        agent.open_file_secure(args.path, process_name=args.process)
        print(f"secure_opened: {args.path} with {args.process}")
    elif args.command == "transparent-open":
        agent.open_file_transparent(args.path)
        print(f"transparent_opened: {args.path}")
    elif args.command == "decrypt-to":
        print(json.dumps(agent.decrypt_to_file_for_approval(args.path, args.output), ensure_ascii=False, indent=2))
    elif args.command == "install-association":
        from agent.file_assoc import install_file_association
        print(install_file_association())
    elif args.command == "uninstall-association":
        from agent.file_assoc import uninstall_file_association
        uninstall_file_association()
        print("association_removed")
    elif args.command == "copy-check":
        print("allowed" if agent.clipboard_check(args.source, args.target) else "blocked")
    elif args.command == "screenshot-check":
        print("allowed" if agent.screenshot_check(args.active_file) else "blocked")
    elif args.command == "usb-check":
        print("allowed" if agent.usb_check(args.operation, args.file) else "blocked")
    elif args.command == "upload-check":
        print("allowed" if agent.network_upload_check(args.file, args.port) else "blocked")
    elif args.command == "export-request":
        print(json.dumps(agent.create_export_request(args.path, args.reason), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
