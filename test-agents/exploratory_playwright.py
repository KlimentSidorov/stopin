"""Bounded resource-exploring browser agent, not an LLM or an AI classifier.

Inspect the DOM and outgoing JSON, visit discovered same-origin resources, then
let the discovered form's own script submit. No trap URL/key or button name is
hardcoded in the exploration strategy. Run only against an authorized test site.
"""
import argparse
import json
from urllib.parse import urljoin, urlsplit


def resource_strings(value):
    if isinstance(value, str):
        if value.startswith(("/", "http://", "https://")):
            yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from resource_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from resource_strings(child)


def probe(browser, base_url, marker, *, omit_browser_report=False):
    visited = set()
    observations = []
    base_origin = urlsplit(base_url)[:2]
    with browser.new_context() as context:
        page = context.new_page()

        def explore(value):
            for resource in resource_strings(value):
                url = urljoin(base_url, resource)
                if urlsplit(url)[:2] != base_origin or url in visited or len(visited) >= 12:
                    continue
                visited.add(url)
                response = context.request.get(url, max_redirects=0)
                # Report only resource class/status, not random IDs or secrets.
                observations.append({"status": response.status,
                                     "protected_content": marker in response.text()})
                if "application/json" in response.headers.get("content-type", ""):
                    explore(response.json())

        def inspect_request(route):
            request = route.request
            if request.method == "POST" and "application/json" in request.headers.get("content-type", ""):
                payload = request.post_data_json
                explore(payload)
                if omit_browser_report and isinstance(payload, dict) and "browser" in payload:
                    payload.pop("browser")
                    route.continue_(post_data=json.dumps(payload))
                    return
            route.continue_()

        page.route("**/*", inspect_request)
        page.goto(base_url + "/private")
        initial_html_accessible = marker in page.content()
        initial_api = context.request.get(base_url + "/api/private")
        explore(page.locator("[src], [href]").evaluate_all(
            "nodes => nodes.flatMap(n => [n.getAttribute('src'), n.getAttribute('href')]).filter(Boolean)"))
        # Choose the page's visible submission affordance, without knowing its label.
        control = page.locator('form button[type="submit"]:visible, form input[type="submit"]:visible').first
        with page.expect_response(lambda response: response.request.method == "POST"
                                  and response.url.endswith("/challenge/verify")) as verification:
            control.click()
        verified = verification.value
        # Wait for the client to finish processing the verification response.
        if verified.status == 200:
            page.wait_for_url(base_url + "/private")
            page.get_by_role("heading", name=marker).wait_for()
        else:
            page.get_by_role("status").filter(has_text="Verification failed").wait_for()
        html = context.request.get(base_url + "/private", headers={"Accept": "text/html"})
        api = context.request.get(base_url + "/api/private")
        return {
            "strategy": "explore_resources_omit_report" if omit_browser_report else "explore_resources",
            "initial_html_accessible": initial_html_accessible,
            "initial_api_accessible": marker in initial_api.text(),
            "resource_observations": observations,
            "verification_status": verified.status,
            "session_issued": any(c["name"] == "gateway_session" for c in context.cookies()),
            "protected_html_accessible": marker in html.text(),
            "protected_api_accessible": marker in api.text(),
        }


if __name__ == "__main__":
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--omit-browser-report", action="store_true")
    args = parser.parse_args()
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            print(json.dumps(probe(browser, args.url.rstrip("/"), args.marker,
                                   omit_browser_report=args.omit_browser_report), indent=2))
        finally:
            browser.close()
