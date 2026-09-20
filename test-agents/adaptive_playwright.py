"""Reusable, bounded browser strategies for an authorized StopIn test gateway.

These are deterministic agents, not LLMs. Only the informed strategy knows which
protocol fields to ignore; explorers follow generic URL/action descriptors.
"""
import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class Strategy:
    name: str
    exploration: str = "none"
    omit_report: bool = False
    informed: bool = False


STRATEGIES = (
    Strategy("normal_visible_flow"),
    Strategy("resource_explorer", "resources"),
    Strategy("protocol_explorer", "protocol"),
    Strategy("telemetry_omitting_explorer", "protocol", omit_report=True),
    Strategy("stopin_aware_adversary", omit_report=True, informed=True),
)


class BrowserExperiment:
    def __init__(self, context, base_url, marker, strategy):
        self.context, self.base_url, self.marker, self.strategy = context, base_url, marker, strategy
        self.origin = urlsplit(base_url)[:2]
        self.visited = set()
        self.resources = []
        self.protocol = None
        self.browser_report_supplied = None
        self.ignored_resources = 0

    def visit(self, value, method="GET", body=None):
        if not isinstance(value, str) or not value.startswith(("/", "http://", "https://")):
            return
        url = urljoin(self.base_url, value)
        parts = urlsplit(url)
        if (parts[:2] != self.origin or parts.username or parts.password or
                method not in ("GET", "POST") or (method, url) in self.visited or len(self.visited) >= 12):
            return
        self.visited.add((method, url))
        response = self.context.request.fetch(url, method=method,
                                              data=body if method == "POST" else None,
                                              max_redirects=0, timeout=10000)
        self.resources.append({"method": method, "status": response.status,
                               "protected_content": self.marker in response.text()})
        if "application/json" in response.headers.get("content-type", ""):
            self.explore(response.json())

    def explore(self, value):
        if isinstance(value, dict):
            if self.strategy.exploration == "protocol" and "url" in value and "method" in value:
                # Follow declared harmless test actions, not arbitrary HTTP verbs.
                self.visit(value["url"], value["method"], value.get("body", {}))
                for key, child in value.items():
                    if key not in ("url", "method", "body"):
                        self.explore(child)
            else:
                for child in value.values():
                    self.explore(child)
        elif isinstance(value, list):
            for child in value:
                self.explore(child)
        elif isinstance(value, str):
            self.visit(value)

    def intercept(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if request.method == "POST" and path == "/challenge":
            response = route.fetch()
            self.protocol = response.json()
            route.fulfill(response=response)
            return
        if request.method == "POST" and path == "/challenge/verify":
            payload = request.post_data_json
            if self.strategy.exploration != "none":
                self.explore(self.protocol)
            if self.strategy.informed:
                self.ignored_resources = len((self.protocol or {}).get("experiments", []))
                # A protocol-aware attacker needs only the normal verification fields.
                payload = {key: payload[key] for key in ("challenge_id", "session_id", "nonce")}
            if self.strategy.omit_report:
                payload.pop("browser", None)
            self.browser_report_supplied = "browser" in payload
            route.continue_(post_data=json.dumps(payload))
            return
        route.continue_()

    def run(self, *, control="mouse"):
        page = self.context.new_page()
        page.route("**/*", self.intercept)
        page.goto(self.base_url + "/private")
        initial_html = self.marker in page.content()
        initial_api = self.marker in self.context.request.get(self.base_url + "/api/private").text()
        if self.strategy.exploration != "none":
            self.explore(page.locator("[src], [href]").evaluate_all(
                "nodes => nodes.flatMap(n => [n.getAttribute('src'), n.getAttribute('href')]).filter(Boolean)"))
        control_checks = {"one_visible_button": page.get_by_role("button").count() == 1,
                          "live_status": page.get_by_role("status").get_attribute("aria-live") == "polite"}
        if control == "slow":
            # Deliberate human-style pause for this control, never a policy threshold.
            page.wait_for_timeout(1200)
        if control == "refresh_back":
            page.reload()
            page.goto(self.base_url + "/challenge?next=/private")
            page.go_back()
        with page.expect_response(lambda r: r.request.method == "POST" and
                                  urlsplit(r.url).path == "/challenge/verify") as verification:
            if control == "keyboard":
                page.keyboard.press("Tab")
                control_checks["keyboard_focus"] = page.get_by_role("button").evaluate(
                    "el => el === document.activeElement")
                page.keyboard.press("Enter")
            else:
                page.locator('form button[type="submit"]:visible, form input[type="submit"]:visible').first.click()
        status = verification.value.status
        if status == 200:
            page.get_by_role("heading", name=self.marker).wait_for()
            if control in ("repeated_navigation", "refresh_back"):
                for _ in range(3):
                    page.reload()
                    page.get_by_role("heading", name=self.marker).wait_for()
                page.goto(self.base_url + "/api/private")
                page.go_back()
                page.get_by_role("heading", name=self.marker).wait_for()
        else:
            page.get_by_role("status").filter(has_text="Verification failed").wait_for()
        html = self.context.request.get(self.base_url + "/private", headers={"Accept": "text/html"})
        api = self.context.request.get(self.base_url + "/api/private")
        return {"strategy": self.strategy.name, "control": control,
                "initial_html_accessible": initial_html, "initial_api_accessible": initial_api,
                "browser_report_supplied": self.browser_report_supplied,
                "verification_status": status,
                "access_session_issued": any(c["name"] == "gateway_session" for c in self.context.cookies()),
                "protected_html_accessible": self.marker in html.text(),
                "protected_api_accessible": self.marker in api.text(),
                "resources": self.resources, "deliberately_ignored_resources": self.ignored_resources,
                "control_checks": control_checks}


def probe(browser, base_url, marker, strategy, *, control="mouse"):
    with browser.new_context() as context:
        return BrowserExperiment(context, base_url.rstrip("/"), marker, strategy).run(control=control)


def attach_server_evidence(result, events):
    """Join sanitized observations to trusted logs from this isolated test run."""
    verification = next(e for e in reversed(events) if e["path"] == "/challenge/verify")
    signals = verification["signals"]
    activated = sorted((e for e in signals["tripwires"]["experiments"] if e["activated"]),
                       key=lambda e: e["activation_order"])
    return {**result, "experiments_activated": [e["family"] for e in activated],
            "activation_order": [{"family": e["family"], "order": e["activation_order"]} for e in activated],
            "verification_decision": verification["decision"],
            "reason_codes": verification["reason_codes"],
            "server_observed_report_presence": signals["behavior"]["browser_report_supplied"],
            "interaction_sequence": signals["behavior"]["interaction_sequence"]}


def main():
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--strategy", choices=[s.name for s in STRATEGIES] + ["all"], default="all")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            results = [probe(browser, args.url, args.marker, strategy) for strategy in STRATEGIES
                       if args.strategy in (strategy.name, "all")]
        finally:
            browser.close()
    text = json.dumps({"server_evidence": "Join gateway logs for activation/order/reason codes",
                       "results": results}, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
