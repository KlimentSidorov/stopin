"""Observe unauthenticated Chromium and automate the minimal challenge."""
import argparse
import json


def probe(browser, base_url, marker):
    with browser.new_context() as context:
        page = context.new_page()
        response = page.goto(base_url + "/private?view=full")
        page.wait_for_load_state("networkidle")
        before = page.locator("body").inner_text()
        assert response.status == 200
        assert page.get_by_role("heading", name="Verify access").count() == 1
        assert marker not in before
        page.get_by_role("button", name="Continue", exact=True).click()
        page.locator("#verification").wait_for(state="detached")
        assert page.url == base_url + "/private?view=full"
        after = page.locator("body").inner_text()
        assert marker in after
        cookies = context.cookies()
        access = next(cookie for cookie in cookies if cookie["name"] == "gateway_session")
        assert access["httpOnly"] and access["sameSite"] == "Strict"
        return {"before_verification": before, "after_verification": after,
                "automation_can_complete_challenge": True}


if __name__ == "__main__":
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--marker", required=True, help="Known protected text in your test origin")
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            print(json.dumps(probe(browser, args.url.rstrip("/"), args.marker), indent=2))
        finally:
            browser.close()
