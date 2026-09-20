import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[2] / "test-agents" / "adaptive_playwright.py"
SPEC = importlib.util.spec_from_file_location("adaptive_playwright", SOURCE)
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def events(caplog):
    return [json.loads(r.message) for r in caplog.records if r.name == "gateway.events"]


@pytest.fixture(scope="module")
def result_matrix(tmp_path_factory):
    rows = []
    yield rows
    artifact = {"recorded_at": datetime.now(timezone.utc).isoformat(),
                "agent_type": "deterministic Playwright strategies, not LLM agents",
                "policy": "existing balanced policy; no new blocking thresholds",
                "runs": rows}
    output = tmp_path_factory.mktemp("adaptive-results") / "adaptive-agent-results.json"
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    # A test-produced artifact can be copied to docs; no production credentials are included.
    print("ADAPTIVE_RESULTS_FILE " + str(output))


@pytest.mark.parametrize("run", range(3))
@pytest.mark.parametrize("strategy", HARNESS.STRATEGIES, ids=lambda s: s.name)
def test_adaptive_strategy_matrix(chromium, live_gateway, caplog, result_matrix, strategy, run):
    caplog.set_level(logging.INFO, logger="gateway.events")
    result = HARNESS.probe(chromium, live_gateway.url, live_gateway.marker, strategy)
    row = HARNESS.attach_server_evidence(result, events(caplog))
    row["run"] = run + 1
    result_matrix.append(row)
    assert not row["initial_html_accessible"] and not row["initial_api_accessible"]
    assert all(not resource["protected_content"] for resource in row["resources"])
    assert row["browser_report_supplied"] == row["server_observed_report_presence"]
    assert all(row["control_checks"].values())
    # Integrity checks measure what happened; they do not impose a detection success target.
    allowed = row["verification_decision"] == "ALLOW"
    assert row["access_session_issued"] == allowed
    assert row["protected_html_accessible"] == allowed
    assert row["protected_api_accessible"] == allowed
    if not allowed:
        assert live_gateway.calls == []
    if strategy.exploration == "none":
        assert row["experiments_activated"] == []
        assert allowed  # Visible-flow bypass is an explicit regression expectation.
    if strategy.informed:
        assert row["deliberately_ignored_resources"] == 3
        assert not row["browser_report_supplied"]
    if strategy.exploration != "none":
        # Probe behavior is checked independently of the policy outcome.
        expected = {"resource", "metadata_reference"}
        if strategy.exploration == "protocol":
            expected.add("protocol_action")
        assert set(row["experiments_activated"]) == expected
    print("ADAPTIVE_RESULT " + json.dumps(row, sort_keys=True))


@pytest.mark.parametrize("control", ["keyboard", "mouse", "slow", "repeated_navigation", "refresh_back"])
def test_false_positive_controls(chromium, live_gateway, caplog, result_matrix, control):
    caplog.set_level(logging.INFO, logger="gateway.events")
    result = HARNESS.probe(chromium, live_gateway.url, live_gateway.marker,
                           HARNESS.STRATEGIES[0], control=control)
    row = HARNESS.attach_server_evidence(result, events(caplog))
    row["strategy"] = "control_" + control
    result_matrix.append(row)
    assert all(row["control_checks"].values())
    assert row["experiments_activated"] == []
    assert row["verification_decision"] == "ALLOW"
    assert row["access_session_issued"]
    assert row["protected_html_accessible"] and row["protected_api_accessible"]
    assert not row["initial_html_accessible"] and not row["initial_api_accessible"]
    assert sum(e["path"] == "/challenge/verify" for e in events(caplog)) == 1
    print("ADAPTIVE_CONTROL " + json.dumps(row, sort_keys=True))
