import importlib.util
import json
import sys
from pathlib import Path

from gateway.app import create_app
from gateway.config import Settings
from conftest import serve


def test_measurement_cohorts(chromium, live_gateway, tmp_path):
    agents = Path(__file__).resolve().parents[2] / "test-agents"
    sys.path.insert(0, str(agents))
    try:
        spec = importlib.util.spec_from_file_location("measurement_playwright", agents / "measurement_playwright.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(agents))
    app = create_app(Settings(measurement_enabled=True, dev_access_token="", rate_limit=1000,
        origin_url=live_gateway.origin_url,
        origin_secret="test-origin-secret-at-least-32-characters"))
    with serve(app) as url:
        artifact = module.collect(chromium, url, live_gateway.marker, pause_seconds=0)
    artifact["collection_context"] = {"browser": "Playwright Chromium", "repetitions_per_strategy": 3,
        "origin": "isolated protected test origin", "policy": "unchanged balanced policy",
        "request_rate_limit": 1000, "note": "Test-only request budget; CLI uses pacing with configured limits."}
    assert all(c["sample_size"] == 0 and c["status"] == "pending" for c in artifact["cohorts"][:3])
    assert all(c["sample_size"] == 3 for c in artifact["cohorts"][3:])
    for run in artifact["runs"]:
        events = run["SERVER_OBSERVED"]["events"]
        assert run["completed"] and run["label"] is None
        assert not run["SERVER_OBSERVED"]["truncated"]
        assert any(e["event"] == "challenge_consumed" for e in events)
        expected_allow = run["cohort"] in ("normal_visible_flow", "telemetry_omitting_explorer", "stopin_aware_adversary")
        assert any(e["event"] == ("session_issued" if expected_allow else "verification_denied") for e in events)
        assert any(e["event"] == "request_started" and e["route"] == "protected_api" for e in events)
        expected_report = run["cohort"] not in ("telemetry_omitting_explorer", "stopin_aware_adversary")
        assert [e["telemetry_present"] for e in events if e["event"] == "verification_submission"] == [expected_report]
    text = json.dumps(artifact, indent=2)
    assert live_gateway.marker not in text
    assert "nonce" not in text and "session_id" not in text and "resource_id" not in text
    output = tmp_path / "human-vs-automation-results.json"
    output.write_text(text + "\n", encoding="utf-8")
    print("MEASUREMENT_RESULTS_FILE " + str(output))
