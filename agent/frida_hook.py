"""
Frida 用户态 API Hook 模块 — Save As 内存加密拦截

将 Frida JS 脚本注入到目标进程（Word/PPT 等），Hook NtWriteFile：
- 若目标是解密临时文件 → 放行
- 若目标是其他受控扩展名文件 → AES-256-CTR 加密 buffer 后再写入磁盘
- 进程退出后 Python 将 CTR 临时文件转为标准 AES-256-GCM .itdlp 格式
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

# ──────────────────────────────────────────────
# Frida JavaScript 注入脚本
# ──────────────────────────────────────────────
FRIDA_SCRIPT = r"""
'use strict';

// ── AES-256 核心（CTR 模式，输出与输入等长）────────
const SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

function subWord(w) {
  return ((SBOX[(w >>> 24) & 0xff] << 24) |
          (SBOX[(w >>> 16) & 0xff] << 16) |
          (SBOX[(w >>> 8) & 0xff] << 8) |
          (SBOX[w & 0xff])) >>> 0;
}
function rotWord(w) { return ((w << 8) | (w >>> 24)) >>> 0; }

function expandKey256(kb) {
  const w = new Array(60);
  for (let i = 0; i < 8; i++)
    w[i] = ((kb[4*i]<<24)|(kb[4*i+1]<<16)|(kb[4*i+2]<<8)|kb[4*i+3])>>>0;
  for (let i = 8; i < 60; i++) {
    let t = w[i-1];
    if (i % 8 === 0) t = subWord(rotWord(t)) ^ (0x01 << ((i/8|0)-1));
    else if (i % 8 === 4) t = subWord(t);
    w[i] = (w[i-8] ^ t) >>> 0;
  }
  return w;
}

function aesEncryptBlock(block, w) {
  let s0=((block[0]<<24)|(block[1]<<16)|(block[2]<<8)|block[3])>>>0^w[0],
      s1=((block[4]<<24)|(block[5]<<16)|(block[6]<<8)|block[7])>>>0^w[1],
      s2=((block[8]<<24)|(block[9]<<16)|(block[10]<<8)|block[11])>>>0^w[2],
      s3=((block[12]<<24)|(block[13]<<16)|(block[14]<<8)|block[15])>>>0^w[3];
  for (let r=1;r<14;r++){const o=r*4;
    const t0=(SBOX[(s0>>>24)&0xff]<<24)|(SBOX[(s1>>>16)&0xff]<<16)|(SBOX[(s2>>>8)&0xff]<<8)|SBOX[s3&0xff];
    const t1=(SBOX[(s1>>>24)&0xff]<<24)|(SBOX[(s2>>>16)&0xff]<<16)|(SBOX[(s3>>>8)&0xff]<<8)|SBOX[s0&0xff];
    const t2=(SBOX[(s2>>>24)&0xff]<<24)|(SBOX[(s3>>>16)&0xff]<<16)|(SBOX[(s0>>>8)&0xff]<<8)|SBOX[s1&0xff];
    s3=((SBOX[(s3>>>24)&0xff]<<24)|(SBOX[(s0>>>16)&0xff]<<16)|(SBOX[(s1>>>8)&0xff]<<8)|SBOX[s2&0xff])>>>0;
    s0=(t0^w[o])>>>0;s1=(t1^w[o+1])>>>0;s2=(t2^w[o+2])>>>0;s3=(s3^w[o+3])>>>0;
  }
  const o=56;
  return new Uint8Array([
    ((SBOX[(s0>>>24)&0xff]<<24)|(SBOX[(s1>>>16)&0xff]<<16)|(SBOX[(s2>>>8)&0xff]<<8)|SBOX[s3&0xff])>>>0^w[o]>>>24&0xff,
    ((SBOX[(s0>>>24)&0xff]<<24)|(SBOX[(s1>>>16)&0xff]<<16)|(SBOX[(s2>>>8)&0xff]<<8)|SBOX[s3&0xff])>>>0^w[o]>>>16&0xff,
    ((SBOX[(s0>>>24)&0xff]<<24)|(SBOX[(s1>>>16)&0xff]<<16)|(SBOX[(s2>>>8)&0xff]<<8)|SBOX[s3&0xff])>>>0^w[o]>>>8&0xff,
    ((SBOX[(s0>>>24)&0xff]<<24)|(SBOX[(s1>>>16)&0xff]<<16)|(SBOX[(s2>>>8)&0xff]<<8)|SBOX[s3&0xff])>>>0^w[o]&0xff,
    ((SBOX[(s1>>>24)&0xff]<<24)|(SBOX[(s2>>>16)&0xff]<<16)|(SBOX[(s3>>>8)&0xff]<<8)|SBOX[s0&0xff])>>>0^w[o+1]>>>24&0xff,
    ((SBOX[(s1>>>24)&0xff]<<24)|(SBOX[(s2>>>16)&0xff]<<16)|(SBOX[(s3>>>8)&0xff]<<8)|SBOX[s0&0xff])>>>0^w[o+1]>>>16&0xff,
    ((SBOX[(s1>>>24)&0xff]<<24)|(SBOX[(s2>>>16)&0xff]<<16)|(SBOX[(s3>>>8)&0xff]<<8)|SBOX[s0&0xff])>>>0^w[o+1]>>>8&0xff,
    ((SBOX[(s1>>>24)&0xff]<<24)|(SBOX[(s2>>>16)&0xff]<<16)|(SBOX[(s3>>>8)&0xff]<<8)|SBOX[s0&0xff])>>>0^w[o+1]&0xff,
    ((SBOX[(s2>>>24)&0xff]<<24)|(SBOX[(s3>>>16)&0xff]<<16)|(SBOX[(s0>>>8)&0xff]<<8)|SBOX[s1&0xff])>>>0^w[o+2]>>>24&0xff,
    ((SBOX[(s2>>>24)&0xff]<<24)|(SBOX[(s3>>>16)&0xff]<<16)|(SBOX[(s0>>>8)&0xff]<<8)|SBOX[s1&0xff])>>>0^w[o+2]>>>16&0xff,
    ((SBOX[(s2>>>24)&0xff]<<24)|(SBOX[(s3>>>16)&0xff]<<16)|(SBOX[(s0>>>8)&0xff]<<8)|SBOX[s1&0xff])>>>0^w[o+2]>>>8&0xff,
    ((SBOX[(s2>>>24)&0xff]<<24)|(SBOX[(s3>>>16)&0xff]<<16)|(SBOX[(s0>>>8)&0xff]<<8)|SBOX[s1&0xff])>>>0^w[o+2]&0xff,
    ((SBOX[(s3>>>24)&0xff]<<24)|(SBOX[(s0>>>16)&0xff]<<16)|(SBOX[(s1>>>8)&0xff]<<8)|SBOX[s2&0xff])>>>0^w[o+3]>>>24&0xff,
    ((SBOX[(s3>>>24)&0xff]<<24)|(SBOX[(s0>>>16)&0xff]<<16)|(SBOX[(s1>>>8)&0xff]<<8)|SBOX[s2&0xff])>>>0^w[o+3]>>>16&0xff,
    ((SBOX[(s3>>>24)&0xff]<<24)|(SBOX[(s0>>>16)&0xff]<<16)|(SBOX[(s1>>>8)&0xff]<<8)|SBOX[s2&0xff])>>>0^w[o+3]>>>8&0xff,
    ((SBOX[(s3>>>24)&0xff]<<24)|(SBOX[(s0>>>16)&0xff]<<16)|(SBOX[(s1>>>8)&0xff]<<8)|SBOX[s2&0xff])>>>0^w[o+3]&0xff
  ]);
}

// ── AES-256-CTR（输出与输入等长，nonce 外传）─────
const fileNonces = {};    // path -> nonce_hex
const roundKeys = {};

function ensureRoundKeys() {
  if (!roundKeys._cached) {
    roundKeys._cached = expandKey256(keyBytes);
  }
  return roundKeys._cached;
}

function ctrEncryptSameSize(path, byteOffset, plainBytes) {
  // 每个文件一个 nonce，从 path+nonce 确定 CTR counter
  if (!fileNonces[path]) {
    const nonce = new Uint8Array(8);
    for (let i = 0; i < 8; i++) nonce[i] = Math.floor(Math.random() * 256);
    let hex = '';
    for (let i = 0; i < 8; i++) hex += ('0' + nonce[i].toString(16)).slice(-2);
    fileNonces[path] = hex;
    send({ type: 'file_nonce', path: path, nonce: hex });
  }

  // 重建 nonce bytes
  const hex = fileNonces[path];
  const nonce = new Uint8Array(8);
  for (let i = 0; i < 8; i++) nonce[i] = parseInt(hex.substr(i*2, 2), 16);

  const rk = ensureRoundKeys();
  const out = new Uint8Array(plainBytes.length);

  // CTR counter = nonce(8) + block_index(8, big-endian, start from byteOffset/16)
  const startBlock = byteOffset >>> 4; // byteOffset / 16
  const counter = new Uint8Array(16);
  for (let i = 0; i < 8; i++) counter[i] = nonce[i];

  const totalBlocks = Math.ceil(plainBytes.length / 16);
  for (let b = 0; b < totalBlocks; b++) {
    const blockIdx = startBlock + b;
    counter[8] = (blockIdx >>> 56) & 0xff;
    counter[9] = (blockIdx >>> 48) & 0xff;
    counter[10] = (blockIdx >>> 40) & 0xff;
    counter[11] = (blockIdx >>> 32) & 0xff;
    counter[12] = (blockIdx >>> 24) & 0xff;
    counter[13] = (blockIdx >>> 16) & 0xff;
    counter[14] = (blockIdx >>> 8) & 0xff;
    counter[15] = blockIdx & 0xff;

    const keystream = aesEncryptBlock(counter, rk);
    const base = b * 16;
    for (let j = 0; j < 16 && (base + j) < plainBytes.length; j++) {
      out[base + j] = plainBytes[base + j] ^ keystream[j];
    }
  }
  return out;
}

// ── 文件路径解析 ─────────────────────────────
function getFilePathFromHandle(handle) {
  try {
    const GetFinalPathNameByHandleW = Module.findExportByName('kernel32.dll', 'GetFinalPathNameByHandleW');
    if (!GetFinalPathNameByHandleW) return null;
    const fn = new NativeFunction(GetFinalPathNameByHandleW, 'uint32', ['pointer', 'pointer', 'uint32', 'uint32']);
    const buf = Memory.alloc(1024);
    const ret = fn(handle, buf, 520, 0);
    if (ret === 0) return null;
    let path = buf.readUtf16String(ret);
    if (path.startsWith('\\\\?\\')) path = path.substring(4);
    return path.toLowerCase();
  } catch (e) { return null; }
}

function isControlledExt(path) {
  if (!path) return false;
  const extList = CONFIG.extensions;
  for (let i = 0; i < extList.length; i++)
    if (path.endsWith(extList[i])) return true;
  return false;
}

// ── 配置 ─────────────────────────────────────
let CONFIG = { key: null, tempFile: null, extensions: [] };
let keyBytes = null;

// ── Hook NtWriteFile ─────────────────────────
// NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)
//                0          1       2           3             4          5      6        7       8
const NtWriteFilePtr = Module.findExportByName('ntdll.dll', 'NtWriteFile');
if (NtWriteFilePtr) {
  Interceptor.attach(NtWriteFilePtr, {
    onEnter(args) {
      if (!keyBytes) return;
      try {
        const handle = args[0];
        const buffer = args[5];       // ← 正确：Buffer 在第 5 个参数
        const length = args[6].toInt32(); // ← 正确：Length 在第 6 个参数
        if (length <= 0 || buffer.isNull()) return;

        const path = getFilePathFromHandle(handle);
        if (!path) return;
        if (CONFIG.tempFile && path === CONFIG.tempFile.toLowerCase()) return;
        if (!isControlledExt(path)) return;

        // 获取写入偏移（用于 CTR counter 定位）
        let byteOffset = 0;
        try {
          const offPtr = args[7]; // PLARGE_INTEGER
          if (!offPtr.isNull()) byteOffset = offPtr.readS64();
        } catch (_) {}

        // CTR 加密（输出与输入等长）
        const plain = buffer.readByteArray(length);
        if (!plain) return;
        const plainArr = new Uint8Array(plain);
        const encrypted = ctrEncryptSameSize(path, byteOffset, plainArr);

        // 分配新内存写入加密数据（等长，无溢出风险）
        const newBuf = Memory.alloc(length);
        newBuf.writeByteArray(Array.from(encrypted));
        args[5] = newBuf; // 替换 Buffer 指针
      } catch (e) {
        // 静默失败，不影响目标进程
      }
    }
  });
}

// ── 接收 Python 配置 ─────────────────────────
recv('config', function onConfig(msg) {
  CONFIG = msg;
  if (CONFIG.key && CONFIG.key.length === 32) {
    keyBytes = new Uint8Array(CONFIG.key);
    roundKeys._cached = null; // 重置密钥缓存
  }
  if (CONFIG.tempFile) CONFIG.tempFile = CONFIG.tempFile.toLowerCase();
  send({ type: 'ready' });
});
"""


# ──────────────────────────────────────────────
# Python 封装类
# ──────────────────────────────────────────────
class FridaSaveAsGuard:
    """Frida Save As 内存加密守卫。

    用法:
        guard = FridaSaveAsGuard(agent, key_bytes, header_dict)
        guard.attach(pid, temp_file_path)     # 注入到目标进程
        ... 用户编辑 ...
        guard.detach()                         # 进程退出后解除注入
        results = guard.finalize()             # 将 CTR 文件转为 .itdlp
    """

    def __init__(self, agent, key: bytes, header: Dict[str, str]) -> None:
        if not HAS_FRIDA:
            raise RuntimeError("frida 未安装，请执行: pip install frida frida-tools")
        self.agent = agent
        self.key = bytes(key)  # 32 bytes
        if len(self.key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        self.header = dict(header)
        self.session: Optional[frida.Session] = None
        self.script = None
        self._save_as_paths: List[str] = []
        self._file_nonces: Dict[str, str] = {}  # path -> nonce(hex)

    def attach(self, pid: int, temp_file_path: str) -> bool:
        """附加到目标进程并注入 Hook 脚本。"""
        try:
            self.session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            print(f"[FridaGuard] 进程 PID={pid} 未找到")
            return False
        except Exception as exc:
            print(f"[FridaGuard] attach 失败: {exc}")
            return False

        try:
            script = self.session.create_script(FRIDA_SCRIPT)
            script.on('message', self._on_message)
            script.load()

            exts = []
            try:
                policy = self.agent.load_policy()
                exts = [e.lower() for e in policy.get("controlled_extensions", [])]
            except Exception:
                exts = [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt"]

            script.post({
                'type': 'config',
                'key': list(self.key),
                'tempFile': str(Path(temp_file_path).resolve()),
                'extensions': exts,
            })
            self.script = script
            print(f"[FridaGuard] 已注入 PID={pid}, temp={temp_file_path}")
            return True
        except Exception as exc:
            print(f"[FridaGuard] 脚本注入失败: {exc}")
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None
            return False

    def detach(self) -> None:
        """解除 Frida 注入。"""
        if self.script:
            try:
                self.script.unload()
            except Exception:
                pass
            self.script = None
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None
        print("[FridaGuard] 已解除注入")

    def finalize(self) -> List[str]:
        """进程退出后，将 CTR 加密文件解密再重加密封装为标准 .itdlp。"""
        from common.crypto_utils import secure_delete

        finalized = []
        for path in self._save_as_paths:
            try:
                if not Path(path).exists():
                    continue

                nonce_hex = self._file_nonces.get(path)
                if not nonce_hex:
                    print(f"[FridaGuard] 缺少 nonce，跳过: {path}")
                    continue

                # 读取 CTR 加密数据
                with open(path, "rb") as f:
                    ctr_data = f.read()
                if len(ctr_data) == 0:
                    continue

                # AES-CTR 解密还原明文
                plaintext = self._ctr_decrypt(nonce_hex, ctr_data)

                # 用标准 AES-256-GCM + .itdlp 头重新加密
                output_path = path + ".itdlp"
                hdr = dict(self.header)
                hdr.pop("nonce", None)
                hdr["original_name"] = Path(path).name
                hdr["created_at"] = str(int(time.time()))
                encrypt_file_for_bytes(plaintext, output_path, self.key, hdr)

                # 删除中间 CTR 文件
                secure_delete(path)
                finalized.append(output_path)
                self.agent.audit(
                    "saveas_frida_intercept", path, "success",
                    {"output": output_path, "original_name": Path(path).name},
                )
                print(f"[FridaGuard] 已转为 .itdlp: {output_path}")
            except Exception as exc:
                print(f"[FridaGuard] finalize 失败 {path}: {exc}")

        self._save_as_paths.clear()
        self._file_nonces.clear()
        return finalized

    def _ctr_decrypt(self, nonce_hex: str, ciphertext: bytes) -> bytes:
        """AES-256-CTR 解密（与 JS 端 ctrEncryptSameSize 相同逻辑）。

        nonce_hex: 16 字符 hex 字符串（8 bytes nonce）
        注意：CTR counter 从块 0 开始，因为 finalize 时对整个文件一次性解密。
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        nonce = bytes.fromhex(nonce_hex)
        counter_block = nonce + b"\x00" * 8
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(counter_block))
        encryptor = cipher.encryptor()
        return encryptor.update(ciphertext) + encryptor.finalize()

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            ptype = payload.get("type", "")
            if ptype == "save_as_file":
                path = payload.get("path", "")
                if path and path not in self._save_as_paths:
                    self._save_as_paths.append(path)
                    print(f"[FridaGuard] 检测到另存为: {path}")
            elif ptype == "file_nonce":
                path = payload.get("path", "")
                nonce = payload.get("nonce", "")
                if path and nonce:
                    self._file_nonces[path] = nonce
            elif ptype == "ready":
                print("[FridaGuard] JS 脚本就绪，Hook 已激活")
        elif message.get("type") == "error":
            print(f"[FridaGuard] JS 错误: {message.get('description', '')}")


def encrypt_file_for_bytes(plaintext: bytes, output_path: str, key: bytes, header: Dict[str, str]) -> None:
    """将字节流加密为标准 .itdlp 文件。"""
    import json as _json
    import tempfile
    from contextlib import suppress

    from common.crypto_utils import MAGIC, HEADER_LEN_SIZE, encrypt_bytes, NONCE_SIZE, KEY_SIZE

    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")
    aad = _json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    nonce, ciphertext = encrypt_bytes(plaintext, key, aad=aad)
    header_json = _json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload = MAGIC + struct.pack(">I", len(header_json)) + header_json + nonce + ciphertext

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp", dir=str(out.parent))
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(payload)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_name, output_path)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


# ── 便捷函数：启动进程并注入 ──────────────────
def spawn_with_hook(agent, exe_path: str, args: List[str], temp_file: str,
                    key: bytes, header: Dict[str, str]) -> Optional[FridaSaveAsGuard]:
    """启动进程并注入 Frida Hook。返回 guard 对象。"""
    if not HAS_FRIDA:
        print("[FridaGuard] frida 未安装，跳过注入")
        return None
    try:
        pid = frida.spawn([exe_path] + args)
        guard = FridaSaveAsGuard(agent, key, header)
        session = frida.attach(pid)
        # 使用 spawn 方式需要先 attach 再 resume
        # 简化：直接用 attach(pid) 方式（需要进程已在运行）
        frida.resume(pid)
        session.detach()
        ok = guard.attach(pid, temp_file)
        if not ok:
            return None
        return guard
    except Exception as exc:
        print(f"[FridaGuard] spawn 失败: {exc}")
        return None
