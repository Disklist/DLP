"""
.itdlp 双击打开入口。

该脚本由 Windows 文件关联调用，不要求当前工作目录位于项目根目录。
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from agent.core import EndpointAgent


def _show_error(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("IT-DLP 文件打开失败", message)
        root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def main() -> int:
    if len(sys.argv) < 2:
        _show_error("缺少要打开的 .itdlp 文件路径")
        return 2

    encrypted_path = sys.argv[1]
    try:
        EndpointAgent().open_file_transparent(encrypted_path)
        return 0
    except Exception as exc:
        _show_error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
