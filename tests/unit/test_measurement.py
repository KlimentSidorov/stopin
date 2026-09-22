import json
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.measurement import PREFIX, CURRENT, Measurements


def client_for(**overrides):
    settings = Settings(measurement_enabled=True, dev_access_token="",
                        origin_secret="measurement-test-origin-secret-32-characters")
    settings = replace(settings, **overrides)
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text="PROTECTED_BODY_SENTINEL")))
    app = create_app(settings, client=upstream)
    return TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1234))


def post(client, path, **kwargs):
    return client.post(PREFIX + path, headers={"Origin": "http://127.0.0.1"}, **kwargs)


def test_completed_manual_run_sanitized_and_label_is_not_authorization():
    with client_for() as client:
        assert post(client, "/start", data={"cohort": "manual_chrome"}).status_code == 200
        assert post(client, "/label").status_code == 409
        assert client.get("/api/private?secret=QUERY_SENTINEL").status_code == 403
        challenge = client.post("/challenge").json()
        assert client.post("/challenge/verify", json=challenge).status_code == 200
        assert client.get("/private", headers={"Accept": "text/html"}).status_code == 200
        assert client.get("/api/private").status_code == 200
        assert post(client, "/finish").status_code == 200
        assert post(client, "/label").status_code == 200
        artifact = client.get(PREFIX + "/export").json()
        text = json.dumps(artifact)
        for forbidden in (*[challenge[k] for k in ("nonce", "session_id", "challenge_id")],
                          "PROTECTED_BODY_SENTINEL", "QUERY_SENTINEL", client.cookies.get("gateway_session")):
            assert forbidden not in text
        row = artifact["runs"][0]
        events = row["SERVER_OBSERVED"]["events"]
        assert row["label"] == "manual-human"
        assert row["SERVER_OBSERVED"]["request_count"] == 5
        assert {"challenge_issued", "experiment_exposed", "verification_submitted", "challenge_consumed",
                "session_issued", "protected_page_requested", "protected_api_requested"} <= {e["event"] for e in events}
        assert artifact["features"]["verification_duration_ms"]["human_observations"][0]["values"]
        client.cookies.delete("gateway_session")
        assert client.get("/api/private?human=true").status_code == 403
        assert post(client, "/start", data={"cohort": "manual_chrome"}).status_code == 200
        assert client.get("/api/private").status_code == 403


def test_namespace_off_remote_host_and_csrf_guards():
    with client_for(measurement_enabled=False) as client:
        assert client.get(PREFIX + "/export").status_code == 404
        assert client.post(PREFIX + "/start").status_code == 404
    with client_for() as client:
        assert client.get(PREFIX, headers={"Host": "evil.example"}).status_code == 404
        assert client.post(PREFIX + "/start", data={"cohort": "manual_chrome"}).status_code == 403
        assert client.post(PREFIX + "/start", headers={"Origin": "https://evil.example"}).status_code == 403
        remote = TestClient(client.app, base_url="http://127.0.0.1", client=("192.0.2.1", 1))
        assert remote.get(PREFIX + "/export").status_code == 404


@pytest.mark.parametrize("overrides", [{"production": True}, {"dev_access_token": "bypass"}, {"trust_railway_proxy": True}])
def test_unsafe_configuration_refused(overrides):
    with pytest.raises(ValueError, match="Measurement requires"):
        client_for(**overrides)


def test_retries_denial_and_untrusted_telemetry():
    with client_for() as client:
        post(client, "/start", data={"cohort": "protocol_explorer"})
        first = client.post("/challenge").json()
        assert client.post("/challenge/verify", json={**first, "nonce": "wrong"}).status_code == 403
        second = client.post("/challenge").json()
        assert client.post("/challenge/verify", json=second).status_code == 200
        post(client, "/finish")
        assert post(client, "/label").status_code == 409
        artifact = client.get(PREFIX + "/export").json()
        assert artifact["features"]["challenge_retries"]["automation_observations"][0]["values"] == {"issuances": 2, "submissions": 2}
        assert artifact["features"]["optional_telemetry"]["automation_observations"][0]["values"] == [False, False]
        assert "verification_rejected" in json.dumps(artifact)
        assert all(c["status"] == "pending" for c in artifact["cohorts"][:3])


def test_bounded_expiring_and_incomplete_samples():
    now = [0]
    recorder = Measurements(clock=lambda: now[0])
    for _ in range(201):
        key = recorder.start("manual_chrome")
    assert len(recorder.runs) == 200
    assert recorder.export()["features"]["optional_telemetry"]["sample_size"]["human_runs"] == 0
    now[0] = 7201
    assert recorder.get(key) is None
    assert recorder.export()["runs"] == []


def test_event_limit_and_completed_run_are_immutable():
    recorder = Measurements()
    key = recorder.start("normal_visible_flow")
    token = CURRENT.set((key, 1))
    try:
        for _ in range(2001):
            recorder.event("request_started")
        run = recorder.get(key)
        assert len(run["events"]) == 2000 and run["truncated"]
        run["completed"] = True
        recorder.event("challenge_issued")
        assert len(run["events"]) == 2000
        assert recorder.export()["cohorts"][3]["sample_size"] == 0
    finally:
        CURRENT.reset(token)
