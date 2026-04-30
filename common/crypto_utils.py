"""
通用加密工具模块（增强版）

在原版基础上增加：
- Argon2 本地主密钥派生
- 安全擦除（3-pass overwrite + delete）
- 密钥内存覆写清零
- 临时文件安全创建与清理
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import struct
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
try:
    from argon2.low_level import Type, hash_secret_raw
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

MAGIC = b"ITDLPENC2"
LEGACY_MAGIC = b"ITDLPENC1"
HEADER_LEN_SIZE = 4
NONCE_SIZE = 12
KEY_SIZE = 32
SECURE_DELETE_CHUNK = 1024 * 1024

# Argon2id 用于本地主密钥派生。参数在普通办公终端上仍可接受，生产环境可继续调大。
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1
PBKDF2_ITERATIONS = 390000


@dataclass
class EncryptedPayload:
    header: Dict[str, str]
    ciphertext: bytes


def derive_master_key(password: str, salt: bytes | None = None, kdf: str | None = None) -> Tuple[bytes, bytes]:
    """使用 Argon2id 从密码派生 256-bit 本地主密钥，返回 (key, salt)。"""
    if salt is None:
        salt = secrets.token_bytes(16)
    if len(salt) < 8:
        raise ValueError("Argon2 salt must be at least 8 bytes")
    selected_kdf = (kdf or ("argon2id" if HAS_ARGON2 else "pbkdf2-sha256")).lower()
    if selected_kdf == "argon2id":
        if not HAS_ARGON2:
            raise RuntimeError("argon2-cffi is required to read this protected key cache")
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )
    elif selected_kdf == "pbkdf2-sha256":
        kdf_obj = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf_obj.derive(password.encode("utf-8"))
    else:
        raise ValueError(f"Unsupported KDF: {selected_kdf}")
    return key, salt


def generate_data_key() -> bytes:
    """生成 AES-256 数据密钥。"""
    return os.urandom(KEY_SIZE)


def encode_key(key: bytes) -> str:
    """将二进制密钥编码为 URL-safe Base64 字符串。"""
    return base64.urlsafe_b64encode(key).decode("ascii")


def decode_key(value: str) -> bytes:
    """从 URL-safe Base64 字符串解码二进制密钥。"""
    return base64.urlsafe_b64decode(value.encode("ascii"))


def encrypt_bytes(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """使用 AES-256-GCM 加密字节流，返回 nonce 与密文。"""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """使用 AES-256-GCM 解密字节流。"""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def pack_encrypted_file(header: Dict[str, str], nonce: bytes, ciphertext: bytes) -> bytes:
    """将文件头、nonce 和密文封装为自描述加密文件格式。"""
    header_json = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return MAGIC + struct.pack(">I", len(header_json)) + header_json + nonce + ciphertext


def unpack_encrypted_file(data: bytes) -> EncryptedPayload:
    """解析自描述加密文件格式。"""
    if data.startswith(MAGIC):
        magic_len = len(MAGIC)
    elif data.startswith(LEGACY_MAGIC):
        magic_len = len(LEGACY_MAGIC)
    else:
        raise ValueError("File is not an IT DLP encrypted file")
    offset = magic_len
    if len(data) < offset + HEADER_LEN_SIZE:
        raise ValueError("Encrypted file is truncated")
    header_len = struct.unpack(">I", data[offset : offset + HEADER_LEN_SIZE])[0]
    offset += HEADER_LEN_SIZE
    if header_len <= 0 or header_len > 1024 * 1024:
        raise ValueError("Encrypted file header length is invalid")
    if len(data) < offset + header_len + NONCE_SIZE:
        raise ValueError("Encrypted file payload is truncated")
    header = json.loads(data[offset : offset + header_len].decode("utf-8"))
    offset += header_len
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]
    header["nonce"] = encode_key(nonce)
    return EncryptedPayload(header=header, ciphertext=ciphertext)


def encrypt_file(input_path: str, output_path: str, key: bytes, header: Dict[str, str]) -> None:
    """加密文件并写入输出路径。"""
    with open(input_path, "rb") as src:
        plaintext = src.read()
    aad = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    nonce, ciphertext = encrypt_bytes(plaintext, key, aad=aad)
    payload = pack_encrypted_file(header, nonce, ciphertext)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(payload)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_name, output)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def write_plain_file_atomic(output_path: str, plaintext: bytes) -> None:
    """原子写入明文临时文件，避免半写入文件被其他进程读取。"""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(plaintext)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_name, output)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def decrypt_file_to_bytes(input_path: str, key: bytes) -> Tuple[Dict[str, str], bytes]:
    """解密文件并返回 (header, plaintext)。"""
    with open(input_path, "rb") as src:
        payload = unpack_encrypted_file(src.read())
    header = dict(payload.header)
    nonce = decode_key(header.pop("nonce"))
    aad = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    plaintext = decrypt_bytes(nonce, payload.ciphertext, key, aad=aad)
    return payload.header, plaintext


def decrypt_file(input_path: str, output_path: str, key: bytes) -> Dict[str, str]:
    """解密文件并写入输出路径，返回解析后的文件头。"""
    header, plaintext = decrypt_file_to_bytes(input_path, key)
    write_plain_file_atomic(output_path, plaintext)
    return header


# ---------------------------------------------------------------------------
# 安全增强功能
# ---------------------------------------------------------------------------


def secure_zero(data: bytearray) -> None:
    """将 bytearray 内容覆写为 0x00。"""
    for i in range(len(data)):
        data[i] = 0


def secure_delete(path: str, passes: int = 3) -> None:
    """对文件进行多遍覆写后安全删除。

    若文件被其他进程锁定导致无法直接删除（常见于 Office 应用），
    Windows 下会使用 MoveFileEx 将删除操作推迟到下次重启；
    其他平台则重命名为 .deleted 后缀。
    """
    file_path = Path(path)
    if not file_path.exists():
        return
    length = file_path.stat().st_size
    try:
        with open(file_path, "r+b") as f:
            for pass_index in range(passes):
                f.seek(0)
                remaining = length
                while remaining > 0:
                    chunk_len = min(SECURE_DELETE_CHUNK, remaining)
                    if pass_index == 0:
                        chunk = b"\x00" * chunk_len
                    elif pass_index == 1:
                        chunk = b"\xff" * chunk_len
                    else:
                        chunk = secrets.token_bytes(chunk_len)
                    f.write(chunk)
                    remaining -= chunk_len
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        _force_remove(file_path)


def _force_remove(file_path: Path) -> None:
    """尝试删除文件；若被锁定则在 Windows 上延迟到重启删除，其他平台重命名。"""
    try:
        file_path.unlink()
        return
    except FileNotFoundError:
        return
    except (PermissionError, OSError):
        pass

    # 文件被锁定，无法直接删除
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
            ctypes.windll.kernel32.MoveFileExW(
                ctypes.c_wchar_p(str(file_path)),
                None,
                MOVEFILE_DELAY_UNTIL_REBOOT,
            )
            return
        except Exception:
            pass

    # 最后兜底：重命名为 .deleted 后缀
    deleted = file_path.with_name(file_path.name + ".deleted")
    try:
        file_path.replace(deleted)
    except Exception:
        pass


class SecureTempFile:
    """创建临时文件，退出上下文时自动安全擦除删除。"""

    def __init__(self, suffix: str = ".tmp") -> None:
        self.fd: int = -1
        self.path: str = ""
        self.suffix = suffix

    def __enter__(self) -> str:
        self.fd, self.path = tempfile.mkstemp(suffix=self.suffix, prefix="itdlp_sec_")
        os.close(self.fd)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        secure_delete(self.path)


def protect_local_key(key_material: bytes, password: str, salt: bytes | None = None) -> Dict[str, str]:
    """用本地主密钥加密数据密钥，返回可持久化存储的字典。"""
    kdf = "argon2id" if HAS_ARGON2 else "pbkdf2-sha256"
    master_key_bytes, salt = derive_master_key(password, salt, kdf=kdf)
    master_key = bytearray(master_key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    try:
        ciphertext = AESGCM(bytes(master_key)).encrypt(nonce, key_material, associated_data=salt)
    finally:
        secure_zero(master_key)
    return {
        "kdf": kdf,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }


def unprotect_local_key(protected: Dict[str, str], password: str) -> bytes:
    """从受保护的存储中恢复数据密钥。"""
    salt = base64.urlsafe_b64decode(protected["salt"].encode("ascii"))
    nonce = base64.urlsafe_b64decode(protected["nonce"].encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(protected["ciphertext"].encode("ascii"))
    master_key_bytes, _ = derive_master_key(password, salt, kdf=protected.get("kdf"))
    master_key = bytearray(master_key_bytes)
    try:
        key_material = AESGCM(bytes(master_key)).decrypt(nonce, ciphertext, associated_data=salt)
        return key_material
    finally:
        secure_zero(master_key)
