"""
USB 外设拷贝阻断模块

通过 watchdog 监控所有可移动磁盘（U 盘）的根目录，
当检测到 .itdlp 文件被写入时，立即删除并上报审计。
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import ctypes
from pathlib import Path
from typing import Callable, List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from agent.core import EndpointAgent
from common.crypto_utils import secure_delete


def list_removable_drives() -> List[str]:
    """枚举 Windows 可移动磁盘盘符。"""
    drives = []
    if sys.platform == "win32":
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    root = f"{chr(65 + i)}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:
                        drives.append(root)
            if drives:
                return drives
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "where", "DriveType=2", "get", "DeviceID", "/value"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith("DeviceID="):
                    drives.append(line.strip().split("=")[1].strip() + "\\")
        except Exception:
            pass
    else:
        # Linux/macOS 简单尝试 /media /Volumes
        for base in ["/media", "/Volumes"]:
            if os.path.isdir(base):
                drives.extend([os.path.join(base, d) for d in os.listdir(base) if os.path.ismount(os.path.join(base, d))])
    return drives


class USBEventHandler(FileSystemEventHandler):
    def __init__(self, agent: EndpointAgent, on_block: Optional[Callable[[str], None]] = None) -> None:
        self.agent = agent
        self.on_block = on_block

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        if event.src_path.lower().endswith(".itdlp"):
            self._block(event.src_path)

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        if event.src_path.lower().endswith(".itdlp"):
            self._block(event.src_path)

    def _block(self, path: str) -> None:
        try:
            for attempt in range(5):
                try:
                    secure_delete(path, passes=1)
                    break
                except Exception:
                    if attempt == 4:
                        raise
                    time.sleep(0.5)
            self.agent.audit("usb_control", path, "blocked", {"operation": "copy_out", "mode": "disabled"})
            msg = f"检测到受控文件写入 U 盘，已拦截删除: {Path(path).name}"
            print(f"[USBGuard] {msg}")
            if self.on_block:
                self.on_block(msg)
        except Exception as exc:
            print(f"[USBGuard] 拦截失败 {path}: {exc}")


class USBGuard:
    """USB 守卫。"""

    def __init__(self, agent: EndpointAgent, on_block: Optional[Callable[[str], None]] = None) -> None:
        self.agent = agent
        self.on_block = on_block
        self.observer = Observer()
        self._handlers: List[USBEventHandler] = []
        self._watched_drives: set[str] = set()
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

    def _refresh_drives(self) -> None:
        drives = set(list_removable_drives())
        if drives == self._watched_drives:
            return
        self.observer.unschedule_all()
        self._watched_drives = set()
        for d in sorted(drives):
            handler = USBEventHandler(self.agent, self.on_block)
            self.observer.schedule(handler, d, recursive=True)
            self._watched_drives.add(d)
            print(f"[USBGuard] 监控 U 盘: {d}")

    def _monitor_loop(self) -> None:
        while self._running:
            self._refresh_drives()
            time.sleep(5)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._refresh_drives()
        self.observer.start()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        print("[USBGuard] 已启动")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.observer.stop()
        self.observer.join()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        print("[USBGuard] 已停止")


if __name__ == "__main__":
    agent = EndpointAgent()
    guard = USBGuard(agent, on_block=lambda msg: print(f"[BLOCK] {msg}"))
    guard.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        guard.stop()
