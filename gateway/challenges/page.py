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
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify access</title></head>
<body><main><h1>Verify access</h1>
<p>Continue to request a short-lived access session.</p>
<form id="verification" data-next="{target}">
<button type="submit">Continue</button></form>
<p id="status" role="status" aria-live="polite"></p>
<noscript>JavaScript is required to complete this verification.</noscript>
</main><script src="/challenge/client.js" defer></script></body></html>"""


CLIENT_SCRIPT = """const form = document.getElementById('verification');
const status = document.getElementById('status');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button');
  button.disabled = true;
  status.textContent = 'Verifying access?';
  try {
    const issued = await fetch('/challenge', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'}, body: '{}'
    });
    if (!issued.ok) throw new Error('issuance failed');
    const challenge = await issued.json();
    const verified = await fetch('/challenge/verify', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(challenge)
    });
    if (!verified.ok) throw new Error('verification failed');
    window.location.assign(form.dataset.next);
  } catch (error) {
    status.textContent = 'Verification failed. Please try again.';
    button.disabled = false;
  }
});
"""
