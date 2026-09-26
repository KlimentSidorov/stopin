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

    # Self-declared AI crawlers and obvious HTTP automation do not receive protected
    # content. This is useful policy evidence, not proof of the caller's identity:
    # a capable client can spoof its User-Agent and browser headers.
    crawler_category = signals.crawler.get("category")
    if crawler_category in ("ai", "automation"):
        return Decision.BLOCK, ["disallowed_crawler"]

    reasons = []
    if signals.tripwires.get("activated"):
        reasons.append("tripwire_activation")
        phase = signals.tripwires.get("activation_phase")
        if phase in ("before_verification", "after_verification_started"):
            reasons.append("trap_" + phase)
        if signals.tripwires.get("replays"):
            reasons.append("trap_replay")
        families = {item["family"] for item in signals.tripwires.get("experiments", [])
                    if item["activated"]}
        if len(families) > 1:
            reasons.append("multiple_experiment_families")
    if signals.rate.get("burst"):
        reasons.append("request_burst")
    if signals.request.get("header_inconsistent"):
        reasons.append("inconsistent_request_headers")
    if signals.browser.get("webdriver"):
        reasons.append("browser_automation_hint")
    if signals.tripwires.get("activated") and signals.rate.get("burst"):
        return Decision.BLOCK, reasons + ["combined_automation_evidence"]
    groups = sum((bool(signals.tripwires.get("activated")), bool(signals.rate.get("burst")),
                  bool(signals.request.get("header_inconsistent")),
                  bool(signals.browser.get("webdriver"))))
    if groups >= 2:
        return Decision.BLOCK, reasons + ["multiple_signal_groups"]
    if signals.session.get("valid"):
        return Decision.ALLOW, reasons + ["valid_verified_session"]

    # Transparent funnel: ordinary top-level HTML navigation is allowed without a
    # visible verification page. Known AI/automation crawlers were rejected above.
    # This is intentionally not called proof of humanity: a sophisticated client can
    # imitate browser headers, so stronger enforcement must combine server evidence.
    if signals.request.get("html_navigation"):
        return Decision.ALLOW, reasons + ["transparent_html_navigation"]
    return Decision.BLOCK, reasons + ["missing_session"]


def evaluate_request(request, settings, sessions, evidence):
    return evaluate_signals(collect_signals(request, settings, sessions, evidence))
