"""
系统托盘客户端主程序

整合 Agent 核心、文件监控、剪贴板守卫、USB 守卫和网络代理，
以系统托盘形式常驻后台运行。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

import pystray
from PIL import Image, ImageDraw

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.core import EndpointAgent
from agent.watcher import DirectoryWatcher
from agent.clipboard_guard import ClipboardGuard
from agent.usb_guard import USBGuard
from agent.net_guard import NetGuard
from agent.file_assoc import install_file_association


def create_icon_image(color: str = "blue") -> Image.Image:
    """生成托盘图标。"""
    width = 64
    height = 64
    image = Image.new("RGB", (width, height), "white")
    dc = ImageDraw.Draw(image)
    if color == "green":
        fill = "#27ae60"
    elif color == "red":
        fill = "#c0392b"
    else:
        fill = "#2980b9"
    dc.ellipse([8, 8, width - 8, height - 8], fill=fill)
    dc.text((width // 2, height // 2), "DLP", fill="white", anchor="mm")
    return image


class TrayApp:
    """托盘应用主类。"""

    def __init__(self) -> None:
        self.agent = EndpointAgent()
        self.watcher: Optional[DirectoryWatcher] = None
        self.clipboard: Optional[ClipboardGuard] = None
        self.usb: Optional[USBGuard] = None
        self.net: Optional[NetGuard] = None
        self.icon: Optional[pystray.Icon] = None
        self._running = False

    def _status_text(self, _item=None) -> str:
        try:
            policy = self.agent.load_policy()
            grace = policy.get("offline_grace_hours", 0)
            cached_at = policy.get("cached_at", 0)
            if time.time() - cached_at < grace * 3600:
                return f"IT-DLP Agent | 终端:{self.agent.config.terminal_id} | 策略版本:{policy.get('version','?')}"
            return f"IT-DLP Agent | 终端:{self.agent.config.terminal_id} | 状态: 离线宽限中"
        except Exception:
            return f"IT-DLP Agent | 终端:{self.agent.config.terminal_id} | 状态: 未连接"

    def _encrypt_file(self) -> None:
        import tkinter as tk
        from tkinter import filedialog, messagebox
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if path:
            try:
                output = self.agent.protect_file(path)
                messagebox.showinfo("成功", f"已加密:\n{output}")
            except Exception as exc:
                messagebox.showerror("失败", str(exc))
        root.destroy()

    def _decrypt_file(self) -> None:
        import tkinter as tk
        from tkinter import filedialog, messagebox
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(title="选择加密文件", filetypes=[("DLP Files", "*.itdlp")])
        if path:
            try:
                # 默认用记事本打开（演示）
                self.agent.open_file_secure(path, "notepad.exe")
            except Exception as exc:
                messagebox.showerror("失败", str(exc))
        root.destroy()

    def _sync_policy(self) -> None:
        import tkinter.messagebox as msgbox
        try:
            self.agent.sync_policy()
            if self.watcher:
                self.watcher.reload_from_policy()
            msgbox.showinfo("成功", "策略同步完成（含监控目录更新）")
        except Exception as exc:
            msgbox.showerror("失败", str(exc))

    def _auto_sync_loop(self) -> None:
        """每 3 秒自动同步策略并更新监控目录。"""
        while self._running:
            time.sleep(3)
            if not self._running:
                break
            try:
                self.agent.sync_policy()
                if self.watcher:
                    self.watcher.reload_from_policy()
            except Exception as exc:
                print(f"[TrayApp] 自动同步策略失败: {exc}")

    def _install_association(self) -> None:
        import tkinter.messagebox as msgbox
        try:
            command = install_file_association()
            msgbox.showinfo("成功", f".itdlp 双击打开关联已修复:\n{command}")
        except Exception as exc:
            msgbox.showerror("失败", str(exc))

    def _open_admin(self, *_args) -> None:
        url = self.agent.config.server_url + "/admin"
        webbrowser.open(url)

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(self._status_text, None, enabled=False),
            pystray.MenuItem("加密文件", lambda _icon, _item: threading.Thread(target=self._encrypt_file, daemon=True).start()),
            pystray.MenuItem("授权打开", lambda _icon, _item: threading.Thread(target=self._decrypt_file, daemon=True).start()),
            pystray.MenuItem("同步策略", lambda _icon, _item: threading.Thread(target=self._sync_policy, daemon=True).start()),
            pystray.MenuItem("修复双击打开", lambda _icon, _item: threading.Thread(target=self._install_association, daemon=True).start()),
            pystray.MenuItem("管理后台", self._open_admin),
            pystray.MenuItem("退出", self._on_exit),
        )

    def _on_exit(self, icon: pystray.Icon, _item=None) -> None:
        self.stop()
        icon.stop()

    def _update_menu(self) -> None:
        while self._running and self.icon:
            try:
                self.icon.menu = self._build_menu()
                self.icon.update_menu()
            except Exception:
                pass
            time.sleep(10)

    def start(self) -> None:
        # 先注册终端
        try:
            self.agent.register()
        except Exception:
            pass

        try:
            install_file_association()
        except Exception as exc:
            print(f"[TrayApp] .itdlp 文件关联安装失败: {exc}")

        # 启动各个守卫
        self.watcher = DirectoryWatcher(self.agent)
        self.watcher.start()

        self.clipboard = ClipboardGuard(
            forbidden_targets=self.agent.load_policy().get("clipboard_forbidden_targets", ["wechat.exe", "qq.exe"]),
            on_block=lambda msg: self.icon and self.icon.notify(msg, "IT-DLP 剪贴板拦截")
        )
        self.clipboard.start()

        self.usb = USBGuard(
            self.agent,
            on_block=lambda msg: self.icon and self.icon.notify(msg, "IT-DLP USB 拦截")
        )
        self.usb.start()

        self.net = NetGuard(self.agent, host="127.0.0.1", port=3128)
        self.net.start()

        self._running = True
        self.icon = pystray.Icon("it_dlp", create_icon_image("blue"), "IT-DLP Agent", self._build_menu())

        # 定时刷新菜单状态
        threading.Thread(target=self._update_menu, daemon=True).start()
        # 定时自动同步策略（含监控目录）
        threading.Thread(target=self._auto_sync_loop, daemon=True).start()

        print("[TrayApp] 系统托盘已启动")
        self.icon.run()

    def stop(self) -> None:
        self._running = False
        if self.watcher:
            self.watcher.stop()
        if self.clipboard:
            self.clipboard.stop()
        if self.usb:
            self.usb.stop()
        if self.net:
            self.net.stop()
        print("[TrayApp] 已退出")


def main() -> None:
    app = TrayApp()
    try:
        app.start()
    except KeyboardInterrupt:
        app.stop()


if __name__ == "__main__":
    main()
