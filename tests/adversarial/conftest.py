import socket
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from gateway.app import create_app
from gateway.config import Settings
from gateway.origin.protection import OriginProtection

MARKER = "MILESTONE4-PROTECTED-ORIGIN-CONTENT"


@contextmanager
def serve(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("Test HTTP server did not start")
            time.sleep(0.01)
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        if thread.is_alive():
            raise RuntimeError("Test HTTP server failed to stop")


@pytest.fixture
def live_gateway():
    origin = FastAPI()
    calls = []

    @origin.get("/private")
    async def private(request: Request):
        calls.append(request.url.path)
        return HTMLResponse(f"<!doctype html><html><body><h1>{MARKER}</h1></body></html>")

    @origin.get("/api/private")
    async def api(request: Request):
        calls.append(request.url.path)
        return {"protected": MARKER}

    secured_origin = OriginProtection(origin, "test-origin-secret-at-least-32-characters")
    with serve(secured_origin) as origin_url:
        app = create_app(Settings(origin_secret="test-origin-secret-at-least-32-characters", origin_url=origin_url, dev_access_token=""))
        with serve(app) as gateway_url:
            yield SimpleNamespace(url=gateway_url, origin_url=origin_url, app=app, calls=calls, marker=MARKER)


@pytest.fixture
def chromium():
    playwright = pytest.importorskip("playwright.sync_api", reason="Install .[adversarial] for Chromium tests")
    with playwright.sync_playwright() as runtime:
        # Missing browser executables are failures, not silently skipped tests.
        browser = runtime.chromium.launch()
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture(scope="session")
def nextjs_origin(tmp_path_factory):
    import os
    import secrets
    import shutil
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "examples" / "nextjs-origin"
    if not shutil.which("node") or not (root / ".next" / "BUILD_ID").exists():
        pytest.skip("Build examples/nextjs-origin to run local Next.js origin tests")
    secret = secrets.token_urlsafe(32)
    log = tmp_path_factory.mktemp("nextjs") / "server.log"
    environment = {**os.environ, "GATEWAY_ORIGIN_SECRET": secret, "PORT": "0",
                   "NODE_ENV": "production", "NEXT_TELEMETRY_DISABLED": "1"}
    with log.open("w") as output:
        process = subprocess.Popen([shutil.which("node"), "server.cjs"], cwd=root,
                                   env=environment, stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 60
            while True:
                text = log.read_text()
                ready = next((line for line in text.splitlines() if line.startswith("ORIGIN_READY ")), None)
                if ready:
                    url = "http://127.0.0.1:" + ready.split()[1]
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Next.js startup failed: " + text)
                time.sleep(0.1)
            yield SimpleNamespace(url=url, secret=secret)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def nextjs_gateway(nextjs_origin):
    settings = Settings(origin_url=nextjs_origin.url, origin_secret=nextjs_origin.secret,
                        dev_access_token="")
    with serve(create_app(settings)) as url:
        yield SimpleNamespace(url=url, origin=nextjs_origin)
