"""
进程完整性校验模块

- 校验进程真实可执行文件路径
- 校验进程数字签名（Windows）
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import psutil


def get_process_path(pid: int) -> Optional[str]:
    """获取进程真实可执行文件路径。"""
    try:
        proc = psutil.Process(pid)
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def verify_process_path(pid: int, expected_names: list[str]) -> bool:
    """校验进程路径中的可执行文件名是否在白名单内。"""
    path = get_process_path(pid)
    if not path:
        return False
    exe_name = Path(path).name.lower()
    return exe_name in [n.lower() for n in expected_names]


def resolve_executable_path(executable: str) -> Optional[str]:
    """解析将要启动的可执行程序真实路径。"""
    candidate = Path(executable)
    if candidate.is_file():
        return str(candidate.resolve())
    resolved = shutil.which(executable)
    if resolved:
        return str(Path(resolved).resolve())
    return None


def is_allowed_executable_name(file_path: str, allowed_names: list[str]) -> bool:
    """检查真实路径的文件名是否在白名单。"""
    return Path(file_path).name.lower() in {name.lower() for name in allowed_names}


def verify_digital_signature(file_path: str) -> bool:
    """
    使用 Windows WinVerifyTrust API 校验 PE 文件数字签名。
    若文件无签名或签名无效返回 False。
    """
    if sys.platform != "win32":
        return True  # 非 Windows 平台跳过签名检查

    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_uint),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_uint),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_uint),
            ("fdwRevocationChecks", ctypes.c_uint),
            ("dwUnionChoice", ctypes.c_uint),
            ("pFile", ctypes.c_void_p),
            ("dwStateAction", ctypes.c_uint),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_uint),
            ("dwUIContext", ctypes.c_uint),
        ]

    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = os.path.abspath(file_path)

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2  # WTD_UI_NONE
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        trust_data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        trust_data.dwStateAction = 0  # WTD_STATEACTION_IGNORE
        trust_data.dwProvFlags = 0x40  # WTD_SAFER_FLAG

        ret = wintrust.WinVerifyTrust(0, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))
        return ret == 0
    except Exception:
        return False


def verify_executable_authorized(executable: str, allowed_names: list[str], check_signature: bool = False) -> tuple[bool, str, Optional[str]]:
    """
    校验准备启动的程序是否授权。
    返回 (authorized, reason, resolved_path)。
    """
    resolved = resolve_executable_path(executable)
    if not resolved:
        return False, f"无法解析可执行程序: {executable}", None
    if not is_allowed_executable_name(resolved, allowed_names):
        return False, f"进程名 {Path(resolved).name.lower()} 不在白名单", resolved
    if check_signature and not verify_digital_signature(resolved):
        return False, f"进程 {Path(resolved).name} 数字签名验证失败", resolved
    return True, "ok", resolved


def verify_process_authorized(pid: int, allowed_names: list[str], check_signature: bool = False) -> tuple[bool, str]:
    """
    综合校验进程是否被授权。
    返回 (authorized: bool, reason: str)
    """
    path = get_process_path(pid)
    if not path:
        return False, "无法获取进程路径"
    exe_name = Path(path).name.lower()
    if exe_name not in [n.lower() for n in allowed_names]:
        return False, f"进程名 {exe_name} 不在白名单"
    if check_signature and not verify_digital_signature(path):
        return False, f"进程 {exe_name} 数字签名验证失败"
    return True, "ok"
