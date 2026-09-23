import re

from fastapi.testclient import TestClient

from gateway.hosted_request_observatory import create_app

TOKEN = "evaluator-token-with-at-least-32-characters"
AUTH = {"Authorization": "Bearer " + TOKEN}


def test_observatory_records_entry_without_sensitive_values():
    app = create_app(evaluator_token=TOKEN, public_base_url="https://pilot.example",
                     cookie_secure=False)
    with TestClient(app, base_url="http://pilot.example") as client:
        created = client.post("/__evaluator/runs", headers=AUTH, json={
            "agent_label": "gemini", "bootstrap_variant": "comment",
            "ttl_seconds": 300}).json()
        path = created["public_url"].removeprefix("https://pilot.example")
        page = client.get(path, headers={
            "User-Agent": "observatory-test-agent",
            "Accept": "text/html",
            "Authorization": "must-not-leak",
            "X-Forwarded-For": "203.0.113.9",
        })
        assert page.status_code == 200
        result = client.get(f'/__observatory/runs/{created["run_id"]}', headers=AUTH)
        assert result.status_code == 200
        body = result.json()
        assert body["summary"]["request_count"] == 1
        assert body["summary"]["routes"] == ["start"]
        observed = body["observations"][0]
        assert observed["headers"]["user-agent"] == "observatory-test-agent"
        assert observed["headers"]["accept"] == "text/html"
        assert "authorization" not in observed["header_names"]
        assert "x-forwarded-for" not in observed["header_names"]
        assert "must-not-leak" not in result.text
        assert "203.0.113.9" not in result.text


def test_observatory_tracks_browser_flow_and_cookie_continuity():
    app = create_app(evaluator_token=TOKEN, public_base_url="https://pilot.example",
                     cookie_secure=False)
    with TestClient(app, base_url="http://pilot.example") as client:
        created = client.post("/__evaluator/runs", headers=AUTH, json={
            "agent_label": "chrome-control", "bootstrap_variant": "comment",
            "ttl_seconds": 300}).json()
        path = created["public_url"].removeprefix("https://pilot.example")
        page = client.get(path)
        script_path = re.search(r'src="([^"]+)"', page.text)[1]
        script = client.get(script_path)
        complete = re.search(r"/__evaluation/complete/[A-Za-z0-9_-]+", script.text)[0]
        protected = re.search(r"/__evaluation/protected/[A-Za-z0-9_-]+", script.text)[0]
        assert client.post(complete).status_code == 204
        assert client.get(protected).status_code == 200

        body = client.get(f'/__observatory/runs/{created["run_id"]}', headers=AUTH).json()
        assert body["summary"]["routes"] == ["start", "script", "complete", "protected"]
        assert body["summary"]["script_requested"] is True
        assert body["summary"]["completion_requested"] is True
        assert body["summary"]["protected_requested"] is True
        assert body["summary"]["cookie_seen_after_entry"] is True


def test_observatory_control_plane_is_private_and_not_self_observed():
    app = create_app(evaluator_token=TOKEN, public_base_url="https://pilot.example",
                     cookie_secure=False)
    with TestClient(app, base_url="http://pilot.example") as client:
        created = client.post("/__evaluator/runs", headers=AUTH, json={
            "agent_label": "agent", "bootstrap_variant": "comment"}).json()
        run_id = created["run_id"]
        assert client.get(f"/__observatory/runs/{run_id}").status_code == 403
        assert client.get(f"/__observatory/runs/{run_id}",
                          headers={"Authorization": "Bearer wrong"}).status_code == 403
        body = client.get(f"/__observatory/runs/{run_id}", headers=AUTH).json()
        assert body["observations"] == []
