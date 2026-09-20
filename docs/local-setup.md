# Try StopIn locally (Windows / PowerShell)

This walkthrough runs the dashboard, Python gateway, and included protected demo
website on your computer. No hosting account, DNS changes, Redis, or Turso is
needed. Keep three PowerShell terminals open while trying it.

| Component | Address | Purpose |
| --- | --- | --- |
| Dashboard | http://127.0.0.1:3001 | Configure a site and inspect traffic |
| Gateway | http://127.0.0.1:8000/private | Visit the website through verification |
| Demo origin | http://127.0.0.1:9000 | Protected website; direct access returns 403 |

## 1. Install dependencies once

You need Python 3.11 or newer and Node.js 20.9 or newer with npm. These are the
minimum versions declared by the local project and its installed Next.js package.
Check your installations:

```powershell
py --version
node --version
npm.cmd --version
```

The commands below use your current workspace location. Adjust the paths if you
move the folders. `StopIn` and `Stopin-Dashboard` must remain sibling folders.

```powershell
cd C:\Users\Kliment\Desktop\python\StopIn
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"

cd C:\Users\Kliment\Desktop\python\Stopin-Dashboard
npm.cmd ci
```

If `.venv` already exists with a suitable Python version, skip creating it.
Calling its Python executable directly avoids PowerShell activation restrictions;
`npm.cmd` similarly avoids restrictions on `npm.ps1`. Dependency installation
requires internet access.

## 2. Terminal 1: start the dashboard and add a site

```powershell
cd C:\Users\Kliment\Desktop\python\Stopin-Dashboard
npm.cmd run dev
```

Open **http://127.0.0.1:3001**, go to **Sites**, and add:

| Field | Value |
| --- | --- |
| Site ID | `local` |
| Domain | `127.0.0.1:8000` |
| Protected origin | `http://127.0.0.1:9000` |

If `local` already exists, check its origin and policy instead. Start with
**Balanced** protection and no route overrides for the walkthrough.

Opening the dashboard initializes `Stopin-Dashboard/data/stopin.db`. Leave
`TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` unset, including in `.env.local`, so
the dashboard and gateway use the same local SQLite database. The traffic view
will initially be empty; visiting the gateway will create real events.

## 3. Terminal 2: start the protected demo website

Generate a secret, print it, and start the origin in this terminal:

```powershell
cd C:\Users\Kliment\Desktop\python\StopIn
$env:GATEWAY_ORIGIN_SECRET = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
$env:GATEWAY_ORIGIN_SECRET
.\.venv\Scripts\python.exe -m uvicorn gateway.origin.demo:create_origin --factory --host 127.0.0.1 --port 9000
```

Copy the printed secret for the next step. Both processes need exactly the same
value. This demo serves a simple page saying **Protected origin content** and a
JSON endpoint at `/api/private`.

## 4. Terminal 3: start the gateway

Replace `PASTE_THE_SECRET_FROM_TERMINAL_2` with the value you just copied:

```powershell
cd C:\Users\Kliment\Desktop\python\StopIn
$env:GATEWAY_ENV = 'development'
$env:GATEWAY_ORIGIN_URL = 'http://127.0.0.1:9000'
$env:GATEWAY_SITE_ID = 'local'
$env:GATEWAY_ORIGIN_SECRET = 'PASTE_THE_SECRET_FROM_TERMINAL_2'
$env:GATEWAY_TOKEN_SECRET = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
$env:GATEWAY_DEV_ACCESS_TOKEN = ''
$env:GATEWAY_COOKIE_SECURE = 'false'
$env:GATEWAY_REDIS_URL = ''
$env:GATEWAY_ALLOWED_HOSTS = '127.0.0.1,localhost'
$env:GATEWAY_TRUST_RAILWAY_PROXY = 'false'
$env:GATEWAY_DASHBOARD_DB = (Resolve-Path '..\Stopin-Dashboard\data\stopin.db').Path
.\.venv\Scripts\python.exe -m uvicorn gateway.app:create_app --factory --host 127.0.0.1 --port 8000
```

Use one gateway worker for this in-memory development setup. The Python gateway
does **not** load `.env` automatically; the commands above set variables for this
terminal. Once connected, the dashboard site's saved origin and policy take
precedence over the gateway's fallback origin setting.

## 5. Try the complete flow

1. Open **http://127.0.0.1:8000/private** in a fresh private/incognito window.
   You should see the challenge page before seeing any protected content.
2. Click **Continue**. After verification you should see **Protected origin content**.
3. In the same browser session, visit **http://127.0.0.1:8000/api/private**.
   You should see JSON containing `"protected": "Protected origin content"`.
4. Visit **http://127.0.0.1:9000/private** directly. It should return an empty
   **403 Forbidden** response, even after gateway verification.
5. Refresh the dashboard and select `local`. Inspect the traffic and event
   details for challenge, allow, and block decisions. Direct origin requests
   do not pass through the gateway and will not appear in its event log.

From another PowerShell terminal, verify that a request without browser cookies
is blocked:

```powershell
curl.exe -i http://127.0.0.1:8000/api/private
```

Expected: HTTP 403 with no protected content.

To try a policy change, add a route rule in the dashboard with pattern `/private`
and action **Block all requests**, then save. Reload the verified browser page:
it should now return 403. Remove that rule and save to restore normal behavior.

The current challenge demonstrates the verification protocol. Browser automation
can also complete it; passing the challenge is not proof that a visitor is human.

## Dashboard-only preview

For a quick UI preview, complete steps 1 and 2 only. Optionally run this in a
separate terminal from `Stopin-Dashboard`:

```powershell
npm.cmd run seed:demo
```

Select the separate `demo-store` site to explore synthetic traffic. It does not
show live gateway activity; use `local` for the full walkthrough.

## Stop and restart

Press **Ctrl+C** in each server terminal to stop it. Repeat steps 2 through 4 to
restart. Site settings and recorded traffic persist in `data/stopin.db`.
In-memory gateway sessions are lost on restart: use a fresh private browser
session or visit **http://127.0.0.1:8000/challenge?next=/private** to verify again.
Keep using `127.0.0.1` consistently because `localhost` has separate cookies.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `Resolve-Path` cannot find `stopin.db` | Open the dashboard and add the site before starting the gateway. Confirm local SQLite is selected. |
| Gateway returns 503 | Confirm the database path, site ID `local`, saved origin, and origin secret. Read the gateway terminal for the error. |
| Gateway returns 502 | Confirm the demo origin is running on port 9000 and the saved origin URL matches. |
| Still getting 403 after verification | Ensure the two origin secrets match, remove any blocking route rule, and try a fresh private browser session. |
| Verification does not persist | Use `GATEWAY_COOKIE_SECURE=false` for this HTTP demo and use the same hostname throughout. |
| No real traffic in the dashboard | Select `local`, refresh, and check that the gateway points to the same local database. |
| Port already in use | Stop the previous server using that port, then rerun the command. |
| HTTP 429 | Wait for the rate-limit window to expire before retrying. |

For a richer protected Next.js demo, see [origin security](origin-security.md).
For deployment requirements, see [production setup](production.md). This
walkthrough uses the dashboard as a local console without public authentication.
