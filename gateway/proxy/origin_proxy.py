from http.cookies import SimpleCookie

import httpx
from fastapi import Request


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def forwarded_headers(request: Request) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() not in {"host", "cookie"}
        and not key.lower().startswith("x-gateway-")
        and key.lower() not in {part.strip().lower() for part in request.headers.get("connection", "").split(",")}
    }
    cookies = SimpleCookie()
    for name, value in request.cookies.items():
        if not name.startswith("gateway_"):
            cookies[name] = value
    if cookies:
        headers["cookie"] = "; ".join(item.OutputString() for item in cookies.values())
    return headers


async def proxy_request(
    client: httpx.AsyncClient,
    request: Request,
    origin_url: str,
    origin_secret: str,
) -> httpx.Response:
    # Development/demo origin used to prove the gateway boundary without requiring
    # a second hosted application. It is reached only after the policy returned ALLOW.
    # Production configuration rejects this scheme and must use a real HTTP(S) origin.
    if origin_url == "builtin://demo":
        path = "/" + request.path_params.get("path", "")
        if path.startswith("/api/"):
            return httpx.Response(200, json={
                "protected": True,
                "message": "STOPIN PROTECTED API CONTENT",
                "access": "This payload was released only after the gateway returned ALLOW.",
            })
        return httpx.Response(
            200,
            text=(
                "<!doctype html><html><head><meta charset='utf-8'>"
                "<title>StopIn Protected Demo</title></head><body>"
                "<h1>STOPIN PROTECTED CONTENT</h1>"
                "<p>If you can read this sentence, the gateway allowed this request.</p>"
                "<p id='secret'>Protected demo value: ORANGE-CASTLE-7429</p>"
                "</body></html>"
            ),
            headers={"content-type": "text/html; charset=utf-8"},
        )

    body = await request.body()
    target_url = f"{origin_url}/{request.path_params['path']}"
    if request.query_params:
        target_url = f"{target_url}?{request.query_params}"

    headers = forwarded_headers(request)
    headers["x-gateway-origin-secret"] = origin_secret
    return await client.request(
        method=request.method,
        url=target_url,
        content=body,
        headers=headers,
        follow_redirects=False,
    )
