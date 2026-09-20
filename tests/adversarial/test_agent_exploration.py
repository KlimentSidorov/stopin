"""Browser controls and the bounded resource-exploration experiment."""
import json
import logging
import runpy
from pathlib import Path

import pytest


def captured_events(caplog):
    return [json.loads(r.message) for r in caplog.records if r.name == "gateway.events"]


@pytest.mark.parametrize("interaction", ["keyboard", "ordinary_playwright"])
def test_visible_flow_never_uses_trap(chromium, live_gateway, caplog, interaction):
    caplog.set_level(logging.INFO, logger="gateway.events")
    with chromium.new_context() as context:
        page = context.new_page()
        resources = []
        page.on("request", lambda request: resources.append(request.url))
        page.goto(live_gateway.url + "/private")
        assert live_gateway.marker not in page.content()
        assert context.request.get(live_gateway.url + "/api/private").status == 403
        assert page.get_by_role("button").count() == 1
        assert page.get_by_role("status").get_attribute("aria-live") == "polite"
        if interaction == "keyboard":
            page.keyboard.press("Tab")
            assert page.get_by_role("button", name="Continue").evaluate("el => el === document.activeElement")
            page.keyboard.press("Enter")
        else:
            page.get_by_role("button", name="Continue").click()
        page.get_by_role("heading", name=live_gateway.marker).wait_for()
        assert live_gateway.marker in context.request.get(live_gateway.url + "/api/private").text()
        assert not any("/challenge/tripwire/" in url for url in resources)
    verification = next(e for e in captured_events(caplog) if e["path"] == "/challenge/verify")
    assert verification["decision"] == "ALLOW"
    assert not verification["signals"]["tripwires"]["activated"]
    assert [e["event"] for e in verification["signals"]["behavior"]["interaction_sequence"]] == [
        "challenge_issued", *(["experiment_exposed"] * 3),
        "verification_submitted", "challenge_consumed", "session_issued"]
    result = {"strategy": interaction, "trap_activated": False, "session_issued": True,
              "policy_reason_codes": verification["reason_codes"],
              "protected_html_accessible": True, "protected_api_accessible": True}
    print("AGENT_EXPERIMENT " + json.dumps(result, sort_keys=True))


@pytest.mark.parametrize("omit_browser_report", [False, True])
def test_resource_exploring_agent(chromium, live_gateway, caplog, tmp_path, omit_browser_report):
    caplog.set_level(logging.INFO, logger="gateway.events")
    source = Path(__file__).resolve().parents[2] / "test-agents" / "exploratory_playwright.py"
    probe = runpy.run_path(str(source))["probe"]
    result = probe(chromium, live_gateway.url, live_gateway.marker,
                   omit_browser_report=omit_browser_report)
    events = captured_events(caplog)
    verification = next(e for e in events if e["path"] == "/challenge/verify")
    result.update(trap_activated=any(e["reason_codes"] == ["tripwire_activation"] for e in events),
                  policy_reason_codes=verification["reason_codes"],
                  interaction_sequence=verification["signals"]["behavior"]["interaction_sequence"])
    assert result["trap_activated"]
    assert not result["initial_html_accessible"] and not result["initial_api_accessible"]
    assert all(not resource["protected_content"] for resource in result["resource_observations"])
    assert "trap_before_verification" in result["policy_reason_codes"]
    # Record the bypass as a regression: an optional browser report can be omitted.
    assert result["session_issued"] is omit_browser_report
    assert result["protected_html_accessible"] is omit_browser_report
    assert result["protected_api_accessible"] is omit_browser_report
    if not omit_browser_report:
        assert "multiple_signal_groups" in result["policy_reason_codes"]
        assert live_gateway.calls == []
    (tmp_path / "agent-interaction-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("AGENT_EXPERIMENT " + json.dumps(result, sort_keys=True))
