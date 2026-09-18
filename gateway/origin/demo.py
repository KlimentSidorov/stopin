"""Runnable protected origin for local integration testing."""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from gateway.origin.protection import OriginProtection


def create_origin():
    origin = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @origin.get("/")
    @origin.get("/private")
    async def page():
        return HTMLResponse("<h1>Protected origin content</h1>")

    @origin.get("/api/private")
    async def api():
        return {"protected": "Protected origin content"}

    return OriginProtection(origin, os.environ.get("GATEWAY_ORIGIN_SECRET", ""))
