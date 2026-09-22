"""Compare operator-confirmed manual traces with Playwright on the SAME lab server."""
import argparse
import json
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

from gateway.pre_application import VARIANTS


def bootstrap_trace(events, number):
    selected = []
    active = False
    for event in events:
        if event['event'] == 'issued' and event['run'] == number:
            active = True
        if active and event['run'] == number:
            selected.append({k: v for k, v in event.items()
                             if k not in ('at', 'order', 'run')})
            if event['event'] == 'response' and event.get('route') == 'private':
                break
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8126')
    parser.add_argument('--manual', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manual = json.loads(args.manual.read_text(encoding='utf-8-sig'))
    with httpx.Client(base_url=args.url) as client:
        before = client.get('/report').json()
        previous = max(r['number'] for r in before['runs'])
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(channel='chrome')
            version = browser.version
            try:
                for variant in VARIANTS:
                    with browser.new_context() as context:
                        page = context.new_page()
                        page.goto(args.url + '/start?variant=' + variant)
                        page.wait_for_url('**/private')
                        assert page.locator('body').inner_text() == 'LAB-PROTECTED-FIXTURE /private'
            finally:
                browser.close()
        after = client.get('/report').json()
    automated = [r for r in after['runs'] if r['number'] > previous]
    comparisons = []
    for variant in VARIANTS:
        human = next(r for r in manual['runs'] if r['variant'] == variant)
        auto = next(r for r in automated if r['variant'] == variant)
        left = bootstrap_trace(manual['events'], human['number'])
        right = bootstrap_trace(after['events'], auto['number'])
        assert left and right
        comparisons.append({'variant': variant, 'manual_run': human['number'],
            'playwright_run': auto['number'], 'equal_action_trace': left == right,
            'manual_trace': left, 'playwright_trace': right})
    result = {'manual_provenance': {'kind': 'operator_report',
        'confirmation': 'all I see LAB-PROTECTED-FIXTURE /private',
        'browser': 'ordinary Chrome as requested; version not independently verified',
        'identity_is_server_verifiable': False},
        'automated_browser': {'channel': 'chrome', 'version': version, 'headless': True},
        'comparison_scope': 'Same lab process and bootstrap; ordered actions, status and body byte counts. '
            'Random IDs, absolute timestamps and global sequence offsets excluded. '
            'HTTP/TLS fingerprints not collected. No claim of wire-level equality.',
        'comparisons': comparisons,
        'automated_events': [e for e in after['events'] if e.get('run') in
                             {r['number'] for r in automated}]}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'comparisons': len(comparisons),
                      'equal_action_traces': sum(c['equal_action_trace'] for c in comparisons)}))


if __name__ == '__main__':
    main()
