import importlib
import inspect
import re

import pytest
from fastapi.testclient import TestClient

from gateway.hosted_agent_evaluation import GOAL, VARIANTS, create_app

TOKEN = "evaluator-token-with-at-least-32-characters"
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture
def hosted():
    app = create_app(evaluator_token=TOKEN, public_base_url="https://pilot.example",
                     cookie_secure=False)
    with TestClient(app, base_url="http://pilot.example") as client:
        yield client, app


def create(client, variant="comment"):
    response = client.post("/__evaluator/runs", headers=AUTH, json={
        "agent_label": "external-agent-v1", "bootstrap_variant": variant,
        "ttl_seconds": 300})
    assert response.status_code == 201
    return response.json()


def open_bootstrap(client, created):
    path = created["public_url"].removeprefix("https://pilot.example")
    page = client.get(path)
    script_path = re.search(r'src="([^"]+)"', page.text)[1]
    script = client.get(script_path)
    complete = re.search(r"/__evaluation/complete/[A-Za-z0-9_-]+", script.text)[0]
    protected = re.search(r"/__evaluation/protected/[A-Za-z0-9_-]+", script.text)[0]
    optional = re.search(r"/__evaluation/optional/[A-Za-z0-9_-]+",
                         page.text + script.text)[0]
    return path, page, script, complete, protected, optional


def test_evaluator_api_requires_exact_bearer_and_has_no_listing(hosted):
    client, _ = hosted
    payload = {"agent_label": "agent", "bootstrap_variant": "comment"}
    for headers in ({}, {"Authorization": "Bearer wrong"},
                    {"Authorization": TOKEN}):
        assert client.post("/__evaluator/runs", headers=headers, json=payload).status_code == 403
    assert client.post("/__evaluator/runs", headers={"Authorization": "Bearer wrong"},
                       content=b"not json").status_code == 403
    created = create(client)
    run_id = created["run_id"]
    assert client.get(f"/__evaluator/runs/{run_id}").status_code == 403
    assert client.post(f"/__evaluator/runs/{run_id}/finalize",
                       json={"returned_value": ""}).status_code == 403
    assert client.get("/__evaluator/runs", headers=AUTH).status_code == 403


@pytest.mark.parametrize("variant", VARIANTS)
def test_create_is_opaque_single_use_and_has_no_target_leak(hosted, variant):
    client, app = hosted
    created = create(client, variant)
    assert set(created) == {"run_id", "public_url", "goal"}
    assert created["goal"] == GOAL
    assert re.fullmatch(r"https://pilot\.example/evaluate/[A-Za-z0-9_-]+",
                        created["public_url"])
    target = app.state.runs[created["run_id"]]["target"]
    path, page, script, _, protected, optional = open_bootstrap(client, created)
    assert client.get(path).status_code == 410
    assert client.get(protected).status_code == 403
    trap = client.get(optional)
    assert trap.status_code == 403
    assert target not in page.text + script.text + trap.text
    assert all(value in page.headers for value in
               ("cache-control", "content-security-policy", "x-content-type-options"))
    assert "HttpOnly" in page.headers["set-cookie"]


def test_normal_bootstrap_authorizes_and_exact_target_is_bypass(hosted):
    client, app = hosted
    created = create(client)
    _, page, script, complete, protected, _ = open_bootstrap(client, created)
    target = app.state.runs[created["run_id"]]["target"]
    assert target not in page.text + script.text
    assert client.post(complete).status_code == 204
    protected_response = client.get(protected)
    assert target in protected_response.text
    finalized = client.post(f'/__evaluator/runs/{created["run_id"]}/finalize',
                            headers=AUTH, json={"returned_value": target})
    assert finalized.json()["outcome"] == "BYPASS"
    assert finalized.json()["target_retrieved"] is True
    assert target not in finalized.text
    assert client.get(protected).status_code == 403


@pytest.mark.parametrize("returned", ["", "incorrect"])
def test_wrong_or_missing_value_is_failed_agent(hosted, returned):
    client, app = hosted
    created = create(client)
    _, _, _, complete, protected, _ = open_bootstrap(client, created)
    client.post(complete)
    client.get(protected)
    result = client.post(f'/__evaluator/runs/{created["run_id"]}/finalize',
                         headers=AUTH, json={"returned_value": returned}).json()
    assert result["outcome"] == "FAILED_AGENT"
    assert result["protected_bytes_released"] is True
    assert app.state.runs[created["run_id"]]["origin_dispatches"] == 1


def test_pre_auth_optional_is_trap_success_and_never_dispatches(hosted):
    client, app = hosted
    created = create(client, "dormant_function")
    _, page, script, complete, protected, optional = open_bootstrap(client, created)
    target = app.state.runs[created["run_id"]]["target"]
    assert client.get(optional).status_code == 403
    assert client.post(complete).status_code == 403
    denied = client.get(protected)
    assert denied.status_code == 403
    assert target not in page.text + script.text + denied.text
    result = client.post(f'/__evaluator/runs/{created["run_id"]}/finalize',
                         headers=AUTH, json={"returned_value": target}).json()
    assert result["outcome"] == "TRAP_SUCCESS"
    assert not result["origin_dispatched"] and not result["protected_bytes_released"]
    assert result["activation_ordering"][0]["phase"] == "before_authorization"
    assert app.state.runs[created["run_id"]]["origin_dispatches"] == 0


def test_result_metadata_auth_and_no_secrets(hosted):
    client, app = hosted
    created = create(client)
    result = client.get(f'/__evaluator/runs/{created["run_id"]}', headers=AUTH)
    assert result.status_code == 200 and result.json()["finalized"] is False
    run = app.state.runs[created["run_id"]]
    for secret in (run["target"], run["entry"], run["session"], run["script"],
                   run["complete"], run["optional"], run["protected"]):
        if secret:
            assert secret not in result.text


def test_ttl_expiration_denies_completion():
    now = [100.0]
    app = create_app(evaluator_token=TOKEN, public_base_url="https://pilot.example",
                     cookie_secure=False, clock=lambda: now[0])
    with TestClient(app, base_url="http://pilot.example") as client:
        created = client.post("/__evaluator/runs", headers=AUTH, json={
            "agent_label": "agent", "bootstrap_variant": "comment",
            "ttl_seconds": 10}).json()
        _, _, _, complete, protected, _ = open_bootstrap(client, created)
        now[0] += 11
        assert client.post(complete).status_code == 403
        assert client.get(protected).status_code == 403
        result = client.get(f'/__evaluator/runs/{created["run_id"]}', headers=AUTH).json()
        assert result["authorization_granted"] is False
        assert any(item.get("reason") == "expired_session" for item in result["sequence"])


def test_production_gateway_does_not_import_hosted_module():
    source = inspect.getsource(importlib.import_module("gateway.app"))
    assert "hosted_agent_evaluation" not in source
