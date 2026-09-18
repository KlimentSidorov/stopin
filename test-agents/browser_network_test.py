"""Inspect fetch, XHR and navigation response bodies before and after verification."""
import argparse
import json


def probe(browser, base_url, marker):
    with browser.new_context() as context:
        page = context.new_page()
        captured = []
        def capture(route):
            # Save bytes before delivering the response: successful verification
            # immediately navigates, which can discard Chromium's response bodies.
            response = route.fetch()
            body = response.body()
            captured.append({"url": response.url, "status": response.status,
                             "body": body.decode("utf-8")})
            route.fulfill(response=response, body=body)

        page.route("**/*", capture)
        page.goto(base_url + "/private")
        page.wait_for_load_state("networkidle")
        fetch = page.evaluate("""async () => {
            const response = await window.fetch('/api/private');
            return {status: response.status, body: await response.text()};
        }""")
        xhr = page.evaluate("""() => new Promise(resolve => {
            const request = new XMLHttpRequest();
            request.open('GET', '/api/private');
            request.onload = () => resolve({status: request.status, body: request.responseText});
            request.send();
        })""")
        assert fetch == xhr == {"status": 403, "body": ""}
        before = list(captured)
        assert before and all(marker not in response["body"] for response in before)
        captured.clear()
        page.get_by_role("button", name="Continue", exact=True).click()
        page.locator("#verification").wait_for(state="detached")
        api = page.evaluate("""async () => {
            const response = await fetch('/api/private');
            return {status: response.status, body: await response.text()};
        }""")
        assert api["status"] == 200 and marker in api["body"]
        after = list(captured)
        # Challenge responses themselves must never contain origin content.
        assert all(marker not in response["body"] for response in after
                   if '/challenge' in response["url"])
        return {"before_verification": before, "unauthenticated_fetch": fetch,
                "unauthenticated_xhr": xhr, "after_verification": after}


if __name__ == "__main__":
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            print(json.dumps(probe(browser, args.url.rstrip("/"), args.marker), indent=2))
        finally:
            browser.close()
