from html import escape
from urllib.parse import unquote, urlsplit


def safe_destination(value: str) -> str:
    decoded = unquote(value)
    try:
        parts = urlsplit(decoded)
    except ValueError:
        return "/"
    if (not decoded.startswith("/") or decoded.startswith("//") or parts.netloc
            or parts.scheme or "\\" in decoded
            or any(ord(char) < 32 for char in decoded)
            or parts.path.startswith("/challenge")):
        return "/"
    return value


def challenge_page(destination: str) -> str:
    target = escape(safe_destination(destination), quote=True)
    # This is a transparent bootstrap, not a CAPTCHA or a human-verification claim.
    # Protected origin bytes are not present in this document.
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Loading</title></head>
<body><main aria-live="polite"><p id="status">Loading…</p>
<form id="verification" data-next="{target}" hidden>
<button type="submit">Continue</button></form>
<noscript>JavaScript is required to access this protected page.</noscript>
</main><script src="/challenge/client.js" defer></script></body></html>"""


CLIENT_SCRIPT = """const form = document.getElementById('verification');
const status = document.getElementById('status');
let running = false;
async function bootstrap(event) {
  if (event) event.preventDefault();
  if (running) return;
  running = true;
  const started = performance.now();
  try {
    const issued = await fetch('/challenge', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: '{}'
    });
    if (!issued.ok) throw new Error('issuance failed');
    const challenge = await issued.json();
    const verified = await fetch('/challenge/verify', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({...challenge, browser: {javascript: true,
        webdriver: navigator.webdriver === true, elapsed_ms: performance.now() - started}})
    });
    if (!verified.ok) throw new Error('verification failed');
    window.location.replace(form.dataset.next);
  } catch (error) {
    status.textContent = 'This page is unavailable.';
    running = false;
  }
}
form.addEventListener('submit', bootstrap);
bootstrap();
"""
