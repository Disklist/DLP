"""
IT DLP 系统增强版一键演示脚本

该脚本会按顺序执行以下操作:
  1. 启动管理控制中心（FastAPI + SQLite + Admin 后台）
  2. 启动系统托盘 Agent（含文件监控、剪贴板守卫、USB 守卫、网络代理）
  3. 执行完整演示流程:
     a. 终端注册与策略同步
     b. 受控文件落地加密 + 安全擦除原文件
     c. 白名单进程授权打开（安全临时文件方式）
     d. 非白名单进程尝试打开（预期被拒绝）
     e. 通道管控检查（剪贴板/截屏/USB/网络上传）
     f. 发起外发解密审批申请
     g. 管理员审批通过（自动添加数字水印）
     h. 查看审计日志与管理后台

使用方式:
    python demo.py

运行前请确保已安装依赖:
    pip install -r requirements.txt
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
SERVER_URL = "http://127.0.0.1:8000"

# ---------------------------------------------------------------------------
# 终端颜色支持（Windows 10+ 支持 ANSI）
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


class Colors:
    """ANSI 终端颜色码。"""
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def run(cmd: list[str], timeout: int = 30) -> str:
    """执行命令并返回 stdout 去空白结果。"""
    result = subprocess.run(
        cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, output=result.stdout, stderr=result.stderr
        )
    return result.stdout.strip()


def run_may_fail(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """执行命令，不抛异常，返回完整 CompletedProcess。"""
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout)


def print_header(text: str) -> None:
    """打印带样式的章节标题。"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")


def print_step(step: int, desc: str) -> None:
    """打印步骤编号和描述。"""
    print(f"{Colors.BOLD}{Colors.YELLOW}[步骤 {step}]{Colors.RESET} {desc}")


def print_success(msg: str) -> None:
    """打印成功消息。"""
    print(f"  {Colors.GREEN}✓{Colors.RESET} {msg}")


def print_failure(msg: str) -> None:
    """打印失败/拒绝消息。"""
    print(f"  {Colors.RED}✗{Colors.RESET} {msg}")


def print_info(msg: str) -> None:
    """打印普通信息。"""
    print(f"  {Colors.DIM}→{Colors.RESET} {msg}")


def wait_server(max_retries: int = 30) -> None:
    """等待服务端就绪。"""
    print_info("等待服务端启动...")
    for i in range(max_retries):
        try:
            resp = requests.get(f"{SERVER_URL}/health", timeout=1)
            if resp.status_code == 200:
                data = resp.json()
                print_success(f"服务端就绪 (v{data.get('version', '?')}, {data.get('service', '?')})")
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"服务端启动超时（已等待 {max_retries * 0.5:.0f} 秒）")


def cleanup_samples() -> None:
    """清理旧的演示样本文件。"""
    samples_dir = ROOT / "demo_samples"
    if samples_dir.exists():
        shutil.rmtree(samples_dir, ignore_errors=True)
    samples_dir.mkdir(exist_ok=True)
    return samples_dir


def main() -> None:
    print_header("IT 终端设备数据加密防泄漏系统 — 增强版演示")

    # -----------------------------------------------------------------------
    # 0. 环境准备
    # -----------------------------------------------------------------------
    print_step(0, "环境准备")
    print_info(f"Python 版本: {sys.version.split()[0]}")
    print_info(f"工作目录: {ROOT}")

    # 清理旧样本
    samples_dir = cleanup_samples()
    sample_file = samples_dir / "sample_secret.txt"
    sample_file.write_text(
        "===== 机密研发资料 =====\n"
        "1. 下一代产品路线图（2026-2027）\n"
        "2. 关键客户名单及联系方式\n"
        "3. 产品定价策略与报价信息\n"
        "4. 核心专利技术方案\n"
        "===========================\n",
        encoding="utf-8",
    )
    print_success(f"已准备样例文件: {sample_file}")

    # -----------------------------------------------------------------------
    # 1. 启动服务端
    # -----------------------------------------------------------------------
    print_header("第一阶段: 启动管理控制中心")

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        wait_server()

        # -------------------------------------------------------------------
        # 2. 终端注册
        # -------------------------------------------------------------------
        print_header("第二阶段: 终端注册与策略同步")

        print_step(1, "Agent 向服务端注册终端")
        reg_result = json.loads(run([sys.executable, "-m", "agent.core", "register"]))
        print_success(f"终端 ID: {reg_result.get('terminal_id', 'N/A')}")
        policy = reg_result.get("policy", {})
        print_info(f"策略版本: v{policy.get('version', '?')}")
        print_info(f"受控扩展名: {', '.join(policy.get('controlled_extensions', [])[:6])} ...")
        print_info(f"离线宽限期: {policy.get('offline_grace_hours', '?')} 小时")

        # -------------------------------------------------------------------
        # 3. 文件加密
        # -------------------------------------------------------------------
        print_header("第三阶段: 受控文件落地自动加密")

        print_step(2, "对受控文件执行 AES-256-GCM 加密")
        run([sys.executable, "-m", "agent.core", "protect", str(sample_file)])
        encrypted_path = str(sample_file) + ".itdlp"
        print_success(f"加密输出: {encrypted_path}")

        # 验证原文件已被安全擦除
        if not sample_file.exists():
            print_success("原明文文件已被安全擦除（3-pass overwrite + delete）")
        else:
            print_failure("警告: 原文件仍存在，加密擦除可能未生效")

        # 验证密文文件存在
        enc_path_obj = Path(encrypted_path)
        if enc_path_obj.exists():
            print_success(f"密文文件已生成 ({enc_path_obj.stat().st_size} bytes)")
        else:
            print_failure("警告: 密文文件不存在")

        # -------------------------------------------------------------------
        # 4. 授权解密
        # -------------------------------------------------------------------
        print_header("第四阶段: 白名单进程授权解密")

        print_step(3, "白名单授权解密验证（自动化测试模式）")
        decrypted_preview = samples_dir / "decrypted_preview.txt"
        decrypted = run_may_fail([
            sys.executable, "-m", "agent.core", "decrypt-to",
            encrypted_path, str(decrypted_preview)
        ])
        if decrypted.returncode == 0 and decrypted_preview.exists():
            preview_text = decrypted_preview.read_text(encoding="utf-8", errors="ignore")
            if "机密研发资料" in preview_text:
                print_success("授权解密成功，明文内容校验通过")
            else:
                print_failure("解密文件已生成，但内容校验未通过")
            decrypted_preview.unlink(missing_ok=True)
        else:
            print_failure(f"授权解密失败: {decrypted.stderr.strip()[:200]}")
        print_info("手动安全打开可执行: python -m agent.core open <file.itdlp> --process notepad.exe")

        print_step(4, "非白名单进程 (hacker.exe) 尝试打开加密文件")
        blocked = run_may_fail([
            sys.executable, "-m", "agent.core", "open",
            encrypted_path, "--process", "hacker.exe"
        ])
        if blocked.returncode != 0:
            print_success(f"hacker.exe 被正确拒绝: {blocked.stderr.strip().splitlines()[-1][:200]}")
        else:
            print_failure("警告: 非白名单进程未被拦截，安全策略可能未生效")

        # -------------------------------------------------------------------
        # 5. 通道管控
        # -------------------------------------------------------------------
        print_header("第五阶段: 通道管控检查")

        print_step(5, "剪贴板外发检查（目标: wechat.exe，预期拦截）")
        cb_result = run([sys.executable, "-m", "agent.core", "copy-check",
                         "--source", encrypted_path, "--target", "wechat.exe"])
        if cb_result == "blocked":
            print_success("剪贴板外发到 wechat.exe 已被拦截")
        else:
            print_failure("警告: 剪贴板检查未正确拦截")

        print_step(6, "截屏检查（活动文件为受控文件，预期拦截）")
        ss_result = run([sys.executable, "-m", "agent.core", "screenshot-check",
                         "--active-file", encrypted_path])
        if ss_result == "blocked":
            print_success("截屏操作已被拦截（受控文件处于活动窗口）")
        else:
            print_failure("警告: 截屏检查未正确拦截")

        print_step(7, "USB 外设拷贝检查（预期拦截）")
        usb_result = run([sys.executable, "-m", "agent.core", "usb-check",
                          "--operation", "copy_out", "--file", encrypted_path])
        if usb_result == "blocked":
            print_success("USB 拷贝受控文件已被拦截")
        else:
            print_failure("警告: USB 检查未正确拦截")

        print_step(8, "网络上传检查（端口 443，预期拦截）")
        net_result = run([sys.executable, "-m", "agent.core", "upload-check",
                          "--file", encrypted_path, "--port", "443"])
        if net_result == "blocked":
            print_success("网络上传受控文件已被拦截")
        else:
            print_failure("警告: 网络上传检查未正确拦截")

        # -------------------------------------------------------------------
        # 6. 外发审批
        # -------------------------------------------------------------------
        print_header("第六阶段: 外发解密审批流程")

        print_step(9, "发起外发解密审批申请")
        export_result = json.loads(
            run([sys.executable, "-m", "agent.core", "export-request",
                 encrypted_path, "--reason", "需发送给客户方项目经理审阅，请审批"])
        )
        req_id = export_result.get("request_id", "")
        print_success(f"审批申请已提交，申请 ID: {req_id}")
        print_info(f"申请状态: {export_result.get('status', 'pending')}")

        print_step(10, "管理员审批通过（自动添加数字水印）")
        approval = requests.post(
            f"{SERVER_URL}/api/export/requests/{req_id}/approve",
            json={
                "approver_id": "admin",
                "approved": True,
                "comment": "同意外发，已自动添加数字水印用于溯源",
            },
            timeout=10,
        ).json()
        print_success(f"审批结果: {approval.get('status', '?')}")
        if approval.get("watermark_file"):
            wm_path = Path(approval["watermark_file"])
            if wm_path.exists():
                print_success(f"水印文件已生成: {wm_path}")
                # 显示水印文件前几行
                try:
                    preview = wm_path.read_text(encoding="utf-8")[:300]
                    print_info(f"水印预览:\n{Colors.DIM}{preview}{Colors.RESET}")
                except Exception:
                    pass
            else:
                print_info("水印文件路径已返回（文件为服务端临时生成）")

        print_step(11, "尝试拒绝审批（验证拒绝流程）")
        # 创建第二个审批来演示拒绝
        export_result2 = json.loads(
            run([sys.executable, "-m", "agent.core", "export-request",
                 encrypted_path, "--reason", "测试拒绝流程"])
        )
        req_id2 = export_result2.get("request_id", "")
        rejection = requests.post(
            f"{SERVER_URL}/api/export/requests/{req_id2}/approve",
            json={
                "approver_id": "admin",
                "approved": False,
                "comment": "该文件包含核心专利信息，不允许外发",
            },
            timeout=10,
        ).json()
        if rejection.get("status") == "rejected":
            print_success(f"审批已正确拒绝: {rejection.get('status')}")
        else:
            print_failure("警告: 审批拒绝流程可能异常")

        # -------------------------------------------------------------------
        # 7. 审计与管理后台
        # -------------------------------------------------------------------
        print_header("第七阶段: 审计日志与管理后台")

        print_step(12, "查询审计日志")
        logs = requests.get(f"{SERVER_URL}/api/audit/logs?limit=50", timeout=5).json()
        print_success(f"审计日志总数: {len(logs)} 条")
        if logs:
            print_info("最近 5 条审计记录:")
            for log in logs[:5]:
                action = log.get("action", "?")
                result = log.get("result", "?")
                file_path = log.get("file_path", "-")
                ts_val = log.get("created_at", 0)
                ts_str = time.strftime("%H:%M:%S", time.localtime(int(ts_val))) if ts_val else "?"
                status_icon = "✓" if result == "success" else "✗" if result == "blocked" else "○"
                print(f"    {Colors.DIM}{ts_str}{Colors.RESET} {status_icon} {action:20s} → {Path(file_path).name if file_path else '-':30s} [{result}]")

        print_step(13, "管理后台")
        print_success(f"管理后台地址: {Colors.BOLD}{Colors.BLUE}{SERVER_URL}/admin{Colors.RESET}")
        print_info("管理后台提供以下功能面板:")
        print_info("  • 终端管理 — 查看注册终端和在线状态")
        print_info("  • 审计日志 — 实时查看所有加密/解密/拦截操作")
        print_info("  • 外发审批 — 审批/拒绝外发申请")
        print_info("  • 策略配置 — 查看/编辑当前生效的安全策略")

        # -------------------------------------------------------------------
        # 完成
        # -------------------------------------------------------------------
        print_header("演示完成")

        print(f"{Colors.GREEN}{Colors.BOLD}  所有 {13} 个演示步骤已执行完毕。{Colors.RESET}\n")
        print(f"  {Colors.CYAN}服务端仍在运行中，你可以:{Colors.RESET}")
        print(f"    {Colors.BOLD}1.{Colors.RESET} 访问管理后台: {Colors.BLUE}{SERVER_URL}/admin{Colors.RESET}")
        print(f"    {Colors.BOLD}2.{Colors.RESET} 手动启动托盘客户端: {Colors.BOLD}python -m agent.tray_app{Colors.RESET}")
        print(f"    {Colors.BOLD}3.{Colors.RESET} 执行更多 Agent 命令: {Colors.BOLD}python -m agent.core --help{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}托盘客户端将自动启动: 文件监控 | 剪贴板守卫 | USB守卫 | 网络代理{Colors.RESET}\n")

        input(f"{Colors.YELLOW}按 Enter 键停止服务端并退出...{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}用户中断演示{Colors.RESET}")
    except Exception as exc:
        print(f"\n{Colors.RED}演示异常: {exc}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理：优雅关闭服务端
        print_info("正在关闭服务端...")
        server.terminate()
        try:
            server.wait(timeout=5)
            print_success("服务端已关闭")
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
            print_info("服务端已强制关闭")

        print_success("演示结束")


if __name__ == "__main__":
    main()
