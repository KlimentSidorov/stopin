from enum import StrEnum

from gateway.detection.engine import collect_signals
from gateway.detection.signals import Signals


class Decision(StrEnum):
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


def evaluate_signals(signals: Signals) -> tuple[Decision, list[str]]:
    """Deterministic prototype policy; reason codes are evidence, not AI scores."""
    if signals.session.get("invalid_token"):
        return Decision.BLOCK, ["invalid_session"]
    if signals.session.get("development"):
        return Decision.ALLOW, ["valid_development_token"]
    reasons = []
    if signals.tripwires.get("activated"):
        reasons.append("tripwire_activation")
    if signals.rate.get("burst"):
        reasons.append("request_burst")
    if signals.request.get("header_inconsistent"):
        reasons.append("inconsistent_request_headers")
    if signals.browser.get("webdriver"):
        reasons.append("browser_automation_hint")
    # Blocking requires two independent server-observed groups.
    if signals.tripwires.get("activated") and signals.rate.get("burst"):
        return Decision.BLOCK, reasons + ["combined_automation_evidence"]
    groups = sum((bool(signals.tripwires.get("activated")), bool(signals.rate.get("burst")),
                  bool(signals.request.get("header_inconsistent")),
                  bool(signals.browser.get("webdriver"))))
    if groups >= 2:
        decision = Decision.CHALLENGE if signals.request.get("html_navigation") else Decision.BLOCK
        return decision, reasons + ["multiple_signal_groups"]
    if signals.session.get("valid"):
        return Decision.ALLOW, reasons + ["valid_verified_session"]
    if signals.request.get("html_navigation"):
        return Decision.CHALLENGE, reasons + ["new_session"]
    return Decision.BLOCK, reasons + ["missing_session"]


def evaluate_request(request, settings, sessions, evidence):
    return evaluate_signals(collect_signals(request, settings, sessions, evidence))
