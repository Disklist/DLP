"""
Windows .itdlp 文件关联注册。

员工电脑安装关联后，双击 .itdlp 会调用 agent/file_opener.py。
外部电脑没有此关联和密钥时，.itdlp 只是普通加密二进制文件。
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

PROG_ID = "ITDLP.EncryptedFile"
EXTENSION = ".itdlp"


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("文件关联注册仅支持 Windows")


def _pythonw_path() -> str:
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        candidate = exe.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(exe)


def _notify_shell_changed() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass


def install_file_association() -> str:
    """为当前用户注册 .itdlp 双击打开关联，返回 open 命令。"""
    _require_windows()
    import winreg

    opener = Path(__file__).resolve().parent / "file_opener.py"
    command = f'"{_pythonw_path()}" "{opener}" "%1"'

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{EXTENSION}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, PROG_ID)
        winreg.SetValueEx(key, "Content Type", 0, winreg.REG_SZ, "application/x-itdlp-encrypted")
        winreg.SetValueEx(key, "PerceivedType", 0, winreg.REG_SZ, "document")

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "IT-DLP Encrypted File")

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}\DefaultIcon") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"{sys.executable},0")

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)

    _notify_shell_changed()
    return command


def _delete_tree(root, subkey: str) -> None:
    import winreg

    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, subkey + "\\" + child)
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        return


def uninstall_file_association() -> None:
    """删除当前用户的 .itdlp 文件关联。"""
    _require_windows()
    import winreg

    _delete_tree(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{EXTENSION}")
    _delete_tree(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROG_ID}")
    _notify_shell_changed()


def main() -> None:
    action = sys.argv[1].lower() if len(sys.argv) > 1 else "install"
    if action == "install":
        command = install_file_association()
        print(f".itdlp 文件关联已安装: {command}")
    elif action in {"uninstall", "remove"}:
        uninstall_file_association()
        print(".itdlp 文件关联已卸载")
    else:
        raise SystemExit("用法: python -m agent.file_assoc [install|uninstall]")


if __name__ == "__main__":
    main()
