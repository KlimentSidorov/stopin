"""Synthetic demo origin for validating StopIn route protection.

This contains no production data. Run behind the gateway and use its unique marker to
verify that blocked clients never receive protected origin content.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from gateway.origin.protection import validate_origin_request

PUBLIC_MARKER = "STOPIN-PUBLIC-DEMO"
PROTECTED_MARKER = "STOPIN-PROTECTED-HUMAN-ONLY-7F4C9A"


def create_app():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    secret = os.getenv("GATEWAY_ORIGIN_SECRET", "")

    def authorized(request: Request):
        return validate_origin_request(request, secret)

    @app.get("/")
    async def home(request: Request):
        if not authorized(request):
            return Response(status_code=403)
        return HTMLResponse(
            "<!doctype html><title>StopIn demo</title>"
            f"<h1>{PUBLIC_MARKER}</h1>"
            "<p>This page is intentionally public through the StopIn policy.</p>"
            '<p><a href="/protected">Open human-only page</a></p>'
        )

    @app.get("/protected")
    async def protected(request: Request):
        if not authorized(request):
            return Response(status_code=403)
        return HTMLResponse(
            "<!doctype html><title>Human-only content</title>"
            "<h1>Human-only content</h1>"
            f"<p id=protected-value>{PROTECTED_MARKER}</p>"
        )

    @app.get("/api/protected")
    async def protected_api(request: Request):
        if not authorized(request):
            return Response(status_code=403)
        return JSONResponse({"protected_value": PROTECTED_MARKER})

    return app


app = create_app()
