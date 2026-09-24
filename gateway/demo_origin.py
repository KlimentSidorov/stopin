"""Synthetic demo origin for validating StopIn route protection.

This contains no production data. Run behind the gateway and use its unique marker to
verify that blocked clients never receive protected origin content.
"""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from gateway.origin.protection import OriginProtection

PUBLIC_MARKER = "STOPIN-PUBLIC-DEMO"
PROTECTED_MARKER = "STOPIN-PROTECTED-HUMAN-ONLY-7F4C9A"


def create_app():
    inner = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @inner.get("/")
    async def home():
        return HTMLResponse(
            "<!doctype html><title>StopIn demo</title>"
            f"<h1>{PUBLIC_MARKER}</h1>"
            "<p>This page is intentionally public through the StopIn policy.</p>"
            '<p><a href="/protected">Open human-only page</a></p>'
        )

    @inner.get("/protected")
    async def protected():
        return HTMLResponse(
            "<!doctype html><title>Human-only content</title>"
            "<h1>Human-only content</h1>"
            f"<p id=protected-value>{PROTECTED_MARKER}</p>"
        )

    @inner.get("/api/protected")
    async def protected_api():
        return JSONResponse({"protected_value": PROTECTED_MARKER})

    # Direct origin requests fail before application routes execute. The credential
    # is stripped by OriginProtection before downstream application code runs.
    return OriginProtection(inner, os.environ["GATEWAY_ORIGIN_SECRET"])
