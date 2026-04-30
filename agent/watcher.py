"""
文件系统监控自动加密模块

使用 watchdog 监控受控目录，当受控扩展名的文件被创建或修改后，
自动加密并安全擦除原明文。
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from agent.core import EndpointAgent


class AutoEncryptHandler(FileSystemEventHandler):
    """自动加密事件处理器。"""

    def __init__(self, agent: EndpointAgent, controlled_exts: Optional[Set[str]] = None) -> None:
        self.agent = agent
        self.controlled_exts = controlled_exts or {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".dwg", ".pdf", ".txt"}
        self._recent: dict[str, float] = {}

    def _should_handle(self, path: str) -> bool:
        if path.endswith(".itdlp"):
            return False
        name = Path(path).name
        if name.startswith("~$") or name.startswith("~"):
            return False  # Office 临时锁文件，跳过
        if Path(path).suffix.lower() not in self.controlled_exts:
            return False
        # 防抖：同一文件 2 秒内不重复处理
        now = time.time()
        if self._recent.get(path, 0) > now - 2:
            return False
        self._recent[path] = now
        return True

    def _wait_until_stable(self, path: str, timeout: float = 20.0) -> bool:
        """等待文件大小和修改时间稳定且文件不再被其他进程锁定。"""
        deadline = time.time() + timeout
        last: tuple[int, float] | None = None
        stable_count = 0
        while time.time() < deadline:
            try:
                stat = Path(path).stat()
                current = (stat.st_size, stat.st_mtime)
            except FileNotFoundError:
                return False
            if current == last and current[0] > 0:
                stable_count += 1
                if stable_count >= 2:
                    # 文件大小和 mtime 已稳定，再确认文件已解锁
                    if self._is_file_unlocked(path):
                        return True
                    stable_count = 0  # 仍被锁定，继续等待
            else:
                stable_count = 0
                last = current
            time.sleep(0.5)
        return False

    @staticmethod
    def _is_file_unlocked(path: str) -> bool:
        """尝试以读写模式打开文件，成功表示未被其他进程独占锁定。"""
        try:
            fd = os.open(path, os.O_RDWR)
            os.close(fd)
            return True
        except (OSError, IOError):
            return False

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        if self._should_handle(event.src_path):
            self._encrypt(event.src_path)

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        if self._should_handle(event.src_path):
            self._encrypt(event.src_path)

    def _encrypt(self, path: str) -> None:
        try:
            if not self._wait_until_stable(path):
                print(f"[AutoEncrypt] 文件未稳定，跳过: {path}")
                return
            output = self.agent.protect_file(path)
            print(f"[AutoEncrypt] {path} -> {output}")
        except Exception as exc:
            print(f"[AutoEncrypt] 失败 {path}: {exc}")


class DirectoryWatcher:
    """受控目录监控器。

    监控目录优先级：
    1. 显式传入 watch_dirs 参数
    2. 策略中的 watch_directories 字段（管理员在后台配置）
    3. 默认值 ~/Documents/受控资料
    """

    def __init__(self, agent: EndpointAgent, watch_dirs: Optional[list[str]] = None) -> None:
        self.agent = agent
        self.observer = Observer()
        self._watches: dict[str, object] = {}  # path -> watchdog watch handle
        try:
            exts = {ext.lower() for ext in agent.load_policy().get("controlled_extensions", [])}
        except Exception:
            exts = None
        self.handler = AutoEncryptHandler(agent, controlled_exts=exts)
        if watch_dirs is not None:
            self.watch_dirs = list(watch_dirs)
        else:
            self.watch_dirs = self._resolve_watch_dirs()

    def _resolve_watch_dirs(self) -> list[str]:
        """从策略中读取监控目录；若策略未配置则使用默认值。"""
        try:
            policy = self.agent.load_policy()
            dirs = policy.get("watch_directories")
            if dirs:
                return [str(d) for d in dirs]
        except Exception:
            pass
        return [str(Path.home() / "Documents" / "受控资料")]

    def start(self) -> None:
        for d in self.watch_dirs:
            os.makedirs(d, exist_ok=True)
            self._watches[d] = self.observer.schedule(self.handler, d, recursive=True)
            print(f"[Watcher] 开始监控: {d}")
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join()

    def add_directory(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)
        self._watches[path] = self.observer.schedule(self.handler, path, recursive=True)
        self.watch_dirs.append(path)
        print(f"[Watcher] 新增监控: {path}")

    def reload_from_policy(self) -> None:
        """从策略重新加载监控目录，动态增删监控路径（无需重启）。

        对被移除的目录，递归解密其中所有 .itdlp 文件后还原为明文。
        """
        new_dirs = set(self._resolve_watch_dirs())
        old_dirs = set(self.watch_dirs)

        for d in old_dirs - new_dirs:
            if d in self._watches:
                self.observer.unschedule(self._watches.pop(d))
            print(f"[Watcher] 停止监控: {d}")
            # 递归解密该目录下所有 .itdlp 文件
            self._decrypt_tree(d)

        for d in new_dirs - old_dirs:
            os.makedirs(d, exist_ok=True)
            self._watches[d] = self.observer.schedule(self.handler, d, recursive=True)
            print(f"[Watcher] 开始监控: {d}")

        if old_dirs != new_dirs:
            self.watch_dirs = sorted(new_dirs)
            print(f"[Watcher] 监控目录已更新: {self.watch_dirs}")

    def _decrypt_tree(self, root_dir: str) -> None:
        """递归遍历目录树，将其中所有 .itdlp 文件解密还原为明文。"""
        count = 0
        for dirpath, _dirnames, filenames in os.walk(root_dir):
            for fname in filenames:
                if not fname.endswith(".itdlp"):
                    continue
                full = os.path.join(dirpath, fname)
                try:
                    self.agent.decrypt_itdlp_in_place(full)
                    count += 1
                    print(f"[Watcher] 已解密: {full}")
                except Exception as exc:
                    print(f"[Watcher] 解密失败 {full}: {exc}")
        if count:
            print(f"[Watcher] {root_dir} 下共解密 {count} 个文件")


if __name__ == "__main__":
    import sys
    agent = EndpointAgent()
    dirs = sys.argv[1:] if len(sys.argv) > 1 else None
    watcher = DirectoryWatcher(agent, watch_dirs=dirs)
    watcher.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()
