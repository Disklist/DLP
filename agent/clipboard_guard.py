"""
剪贴板管控模块（Windows）

通过注册剪贴板查看器监听 WM_DRAWCLIPBOARD 消息，
当检测到受控内容被粘贴到黑名单进程时，清空剪贴板。
"""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from typing import Callable, Optional

import psutil

IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    import win32api
    import win32clipboard
    import win32con
    import win32gui
    from ctypes import wintypes

WM_CLIPBOARDUPDATE = 0x031D


class ClipboardGuard:
    """剪贴板守卫。"""

    def __init__(self, forbidden_targets: Optional[list[str]] = None, on_block: Optional[Callable[[str], None]] = None) -> None:
        self.forbidden = [p.lower() for p in (forbidden_targets or ["wechat.exe", "qq.exe", "telegram.exe"])]
        self.on_block = on_block
        self._hwnd: Optional[int] = None
        self._next_hwnd: Optional[int] = None
        self._listener_mode = ""
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._controlled_until = 0.0

    def mark_controlled_clipboard(self, ttl_seconds: int = 45) -> None:
        """外部模块确认当前剪贴板来自受控文件时，可调用此方法设置短期拦截窗口。"""
        self._controlled_until = time.time() + ttl_seconds

    def _create_window(self) -> int:
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = self._wnd_proc
        wc.lpszClassName = "ITDLPClipboardGuard"
        wc.hInstance = win32api.GetModuleHandle(None)
        try:
            win32gui.RegisterClass(wc)
        except Exception:
            pass
        hwnd = win32gui.CreateWindow(
            "ITDLPClipboardGuard", "ITDLPClipboardGuard",
            0, 0, 0, 0, 0, 0, 0, wc.hInstance, None
        )
        return hwnd

    def _wnd_proc(self, hwnd, msg, wparam, lparam) -> int:
        if msg == WM_CLIPBOARDUPDATE:
            self._on_clipboard_change()
        elif msg == win32con.WM_DRAWCLIPBOARD:
            self._on_clipboard_change()
            if self._next_hwnd:
                win32gui.SendMessage(self._next_hwnd, msg, wparam, lparam)
        elif msg == win32con.WM_CHANGECBCHAIN:
            if wparam == self._next_hwnd:
                self._next_hwnd = lparam
            elif self._next_hwnd:
                win32gui.SendMessage(self._next_hwnd, msg, wparam, lparam)
        elif msg == win32con.WM_DESTROY:
            self._unregister_clipboard_listener(hwnd)
            win32gui.PostQuitMessage(0)
        else:
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
        return 0

    def _register_clipboard_listener(self, hwnd: int) -> None:
        """
        优先使用 Vista+ 的 AddClipboardFormatListener。
        少数 pywin32 版本没有 SetClipboardViewer 包装，因此旧剪贴板链用 ctypes 兜底。
        """
        user32 = ctypes.windll.user32
        add_listener = getattr(user32, "AddClipboardFormatListener", None)
        if add_listener:
            add_listener.argtypes = [wintypes.HWND]
            add_listener.restype = wintypes.BOOL
            if add_listener(hwnd):
                self._listener_mode = "format_listener"
                return

        set_viewer = user32.SetClipboardViewer
        set_viewer.argtypes = [wintypes.HWND]
        set_viewer.restype = wintypes.HWND
        self._next_hwnd = set_viewer(hwnd)
        self._listener_mode = "viewer_chain"

    def _unregister_clipboard_listener(self, hwnd: int) -> None:
        try:
            user32 = ctypes.windll.user32
            if self._listener_mode == "format_listener":
                remove_listener = getattr(user32, "RemoveClipboardFormatListener", None)
                if remove_listener:
                    remove_listener.argtypes = [wintypes.HWND]
                    remove_listener.restype = wintypes.BOOL
                    remove_listener(hwnd)
            elif self._listener_mode == "viewer_chain" and self._next_hwnd:
                change_chain = user32.ChangeClipboardChain
                change_chain.argtypes = [wintypes.HWND, wintypes.HWND]
                change_chain.restype = wintypes.BOOL
                change_chain(hwnd, self._next_hwnd)
        except Exception:
            pass

    def _on_clipboard_change(self) -> None:
        # 获取当前前台窗口所属进程
        try:
            hwnd = win32gui.GetForegroundWindow()
            _, pid = win32gui.GetWindowThreadProcessId(hwnd)
            proc = psutil.Process(pid)
            exe = proc.exe()
            exe_name = proc.name().lower()
        except Exception:
            return

        if exe_name not in self.forbidden:
            return

        if not self._clipboard_contains_controlled_data():
            return

        # 清空剪贴板
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
        except Exception:
            pass

        msg = f"剪贴板外发到 {exe_name} 已被拦截"
        print(f"[ClipboardGuard] {msg}")
        if self.on_block:
            self.on_block(msg)

    def _clipboard_contains_controlled_data(self) -> bool:
        if time.time() < self._controlled_until:
            return True
        try:
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                    paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                    if any(str(path).lower().endswith(".itdlp") for path in paths):
                        return True
                for fmt in (win32con.CF_UNICODETEXT, win32con.CF_TEXT):
                    if win32clipboard.IsClipboardFormatAvailable(fmt):
                        data = win32clipboard.GetClipboardData(fmt)
                        if isinstance(data, bytes):
                            text = data.decode("utf-8", errors="ignore")
                        else:
                            text = str(data)
                        lowered = text.lower()
                        if "itdlpenc1" in lowered or "itdlpenc2" in lowered or "confidential" in lowered:
                            return True
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            return False
        return False

    def _run(self) -> None:
        try:
            self._hwnd = self._create_window()
            self._register_clipboard_listener(self._hwnd)
            win32gui.PumpMessages()
        except Exception as exc:
            self._running = False
            print(f"[ClipboardGuard] 启动失败: {exc}")

    def start(self) -> None:
        if self._running:
            return
        if not IS_WINDOWS:
            print("[ClipboardGuard] 非 Windows 平台，剪贴板守卫跳过")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print("[ClipboardGuard] 已启动")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._hwnd:
            try:
                win32gui.PostMessage(self._hwnd, win32con.WM_DESTROY, 0, 0)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        print("[ClipboardGuard] 已停止")


if __name__ == "__main__":
    if not IS_WINDOWS:
        raise SystemExit("clipboard_guard 仅支持 Windows")

    def on_block(msg: str) -> None:
        win32api.MessageBox(0, msg, "IT-DLP 剪贴板拦截", win32con.MB_ICONWARNING)

    guard = ClipboardGuard(on_block=on_block)
    guard.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        guard.stop()
