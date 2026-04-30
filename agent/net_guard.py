"""
网络外发代理阻断模块

启动本地 HTTP/HTTPS 代理，在代理层检查上传流量。
若检测到受控文件特征（.itdlp 魔数头或文件名匹配），直接返回 403。
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from typing import Optional

from aiohttp import web

from agent.core import EndpointAgent

MAGICS = (b"ITDLPENC2", b"ITDLPENC1")
CONTROLLED_NAME_RE = re.compile(
    rb'filename\*?=(?:UTF-8\'\')?"?[^"\r\n;]*(?:\.itdlp|\.docx|\.xlsx|\.pptx|\.pdf|\.txt)(?:\.itdlp)?"?',
    re.IGNORECASE,
)
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class UploadInterceptor:
    """上传拦截器。"""

    def __init__(self, agent: EndpointAgent) -> None:
        self.agent = agent

    async def handle(self, request: web.Request) -> web.Response:
        if request.method.upper() == "CONNECT":
            target = request.match_info.get("path", "")
            self.agent.audit("network_upload_control", target, "blocked", {"reason": "https_connect_not_inspected"})
            return web.Response(
                status=403,
                text="IT-DLP: HTTPS CONNECT tunnel blocked by user-mode proxy. Use an enterprise TLS inspection gateway for HTTPS body inspection.",
            )

        # 读取请求体
        try:
            body = await request.read()
        except Exception:
            body = b""

        # 检查是否包含受控文件魔数
        if any(magic in body for magic in MAGICS) or CONTROLLED_NAME_RE.search(body):
            self.agent.audit("network_upload_control", str(request.rel_url), "blocked", {"reason": "controlled_payload"})
            return web.Response(status=403, text="IT-DLP: Upload of controlled file blocked")

        # 检查 URL 或 Header 中是否出现受控扩展名
        url = self._target_url(request)
        if any(ext in url.lower() for ext in [".itdlp", ".docx.itdlp", ".pdf.itdlp"]):
            self.agent.audit("network_upload_control", url, "blocked", {"reason": "controlled_url"})
            return web.Response(status=403, text="IT-DLP: Upload of controlled file blocked")

        # 转发到目标（简单透明代理）
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                method = request.method
                headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "host"}
                async with session.request(method, url, headers=headers, data=body, ssl=False) as resp:
                    resp_body = await resp.read()
                    response_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
                    return web.Response(status=resp.status, body=resp_body, headers=response_headers)
        except Exception as exc:
            return web.Response(status=502, text=f"Proxy error: {exc}")

    @staticmethod
    def _target_url(request: web.Request) -> str:
        raw = request.raw_path
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        host = request.headers.get("Host")
        if not host:
            raise web.HTTPBadRequest(text="Proxy request missing Host header")
        return f"http://{host}{raw}"


class NetGuard:
    """网络守卫。"""

    def __init__(self, agent: EndpointAgent, host: str = "127.0.0.1", port: int = 3128) -> None:
        self.agent = agent
        self.host = host
        self.port = port
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    async def _build_app(self) -> web.Application:
        interceptor = UploadInterceptor(self.agent)
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", interceptor.handle)
        return app

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._app = loop.run_until_complete(self._build_app())
        self._runner = web.AppRunner(self._app)
        loop.run_until_complete(self._runner.setup())
        site = web.TCPSite(self._runner, self.host, self.port)
        loop.run_until_complete(site.start())
        print(f"[NetGuard] 代理已启动 {self.host}:{self.port}")
        while self._running:
            loop.run_until_complete(asyncio.sleep(1))
        loop.run_until_complete(self._runner.cleanup())

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[NetGuard] 已停止")


if __name__ == "__main__":
    agent = EndpointAgent()
    guard = NetGuard(agent, host="127.0.0.1", port=3128)
    guard.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        guard.stop()
