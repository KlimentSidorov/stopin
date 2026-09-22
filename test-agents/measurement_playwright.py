"""Collect comparable local measurement runs using the existing M10 strategies."""
import argparse
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from adaptive_playwright import BrowserExperiment, STRATEGIES


def collect(browser, url, marker, repetitions=3, pause_seconds=15):
    url = url.rstrip("/")
    if urlsplit(url).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Measurement collector requires a loopback gateway")
    first = True
    for strategy in STRATEGIES:
        for _ in range(repetitions):
            if not first:
                time.sleep(pause_seconds)
            first = False
            with browser.new_context() as context:
                response = context.request.post(url + "/__measurement/start",
                    form={"cohort": strategy.name}, headers={"Origin": url})
                if response.status != 200:
                    raise RuntimeError(f"Start measurement failed: {response.status}")
                BrowserExperiment(context, url, marker, strategy).run()
                response = context.request.post(url + "/__measurement/finish", headers={"Origin": url})
                if response.status != 200:
                    raise RuntimeError(f"Finish measurement failed: {response.status}")
    with browser.new_context() as context:
        response = context.request.get(url + "/__measurement/export")
        if response.status != 200:
            raise RuntimeError(f"Export measurement failed: {response.status}")
        return response.json()


if __name__ == "__main__":
    from playwright.sync_api import sync_playwright
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--marker", default="Protected origin content")
    parser.add_argument("--repetitions", type=int, default=3, choices=range(1, 11))
    parser.add_argument("--output", type=Path, default=Path("docs/human-vs-automation-results.json"))
    args = parser.parse_args()
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            artifact = collect(browser, args.url, args.marker, args.repetitions)
        finally:
            browser.close()
    args.output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"Saved sanitized measurements to {args.output}; manual samples are never synthesized.")
