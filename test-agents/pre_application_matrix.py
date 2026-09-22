"""Controlled strategy models, not claims of testing a general-purpose LLM agent."""
import json
import re
from html.parser import HTMLParser

import httpx

from gateway.pre_application import VARIANTS

PROTECTED = ('/private', '/api/private', '/_next/data/lab/private.json', '/_next/static/lab.js')
STRATEGIES = ('normal_playwright', 'html_parser_no_js', 'resource_explorer',
              'protocol_js_explorer', 'agent_like_solver', 'stopin_aware_minimal',
              'no_js_minimal_protocol', 'late_resource_explorer')


class BootstrapParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and 'src' in attrs:
            self.script = attrs['src']


def endpoints(html, script):
    optional = re.search(r'/__trap/optional/[A-Za-z0-9_-]+', html + script)
    complete = re.search(r'/__trap/complete/[A-Za-z0-9_-]+', script)
    return optional[0] if optional else None, complete[0] if complete else None


def collect(browser, url, app, origin_calls, repetitions=3):
    results = []
    for variant in VARIANTS:
        for strategy in STRATEGIES:
            for repetition in range(repetitions):
                start = len(app.state.events)
                before = len(origin_calls)
                responses = []
                if strategy in ('html_parser_no_js', 'protocol_js_explorer',
                                'no_js_minimal_protocol'):
                    with httpx.Client(base_url=url) as client:
                        html = client.get('/start', params={'variant': variant}).text
                        parser = BootstrapParser()
                        parser.feed(html)
                        if strategy != 'html_parser_no_js':
                            script = client.get(parser.script).text
                            optional, complete = endpoints(html, script)
                            if strategy == 'protocol_js_explorer':
                                responses.append(client.get(optional))
                            responses.append(client.post(complete))
                        responses.extend(client.get(path) for path in PROTECTED)
                        bodies = [r.content for r in responses]
                else:
                    context = browser.new_context()
                    try:
                        page = context.new_page()
                        # Early explorers inspect before running the legitimate script.
                        # This ordering is a strategy choice, not enforced on adversaries.
                        early = strategy in ('resource_explorer', 'agent_like_solver')
                        if early:
                            page.route('**/__trap/script/*', lambda route: route.abort())
                        page.goto(url + '/start?variant=' + variant)
                        if early:
                            html = page.content()
                            script_url = page.locator('script[src]').get_attribute('src')
                            script = context.request.get(url + script_url).text()
                            optional, complete = endpoints(html, script)
                            if strategy == 'agent_like_solver':
                                # Interpret the recovery/index/helper clue as a way to
                                # obtain the app; this is explicitly a scripted heuristic.
                                assert any(word in html + script for word in
                                           ('recovery', 'application_index', 'stopinOptionalRecovery'))
                            responses.append(context.request.get(url + optional))
                            responses.append(context.request.post(url + complete))
                        else:
                            page.wait_for_url('**/private')
                            if strategy == 'late_resource_explorer':
                                # A real bypass: explore only after normal JS has authorized.
                                sid = next(c['value'] for c in context.cookies()
                                           if c['name'] == 'stopin_lab_session')
                                optional = '/__trap/optional/' + app.state.sessions[sid]['optional']
                                responses.append(context.request.get(url + optional))
                        responses.extend(context.request.get(url + path) for path in PROTECTED)
                        bodies = [r.body() for r in responses]
                    finally:
                        context.close()
                events = app.state.events[start:]
                allowed = strategy in ('normal_playwright', 'stopin_aware_minimal',
                                       'no_js_minimal_protocol')
                late = strategy == 'late_resource_explorer'
                dispatched = len(origin_calls) - before
                assert dispatched > 0 if allowed or late else dispatched == 0
                if not allowed:
                    assert all(b'PROTECTED' not in body for body in bodies)
                    if not late:
                        assert all(e.get('protected_bytes', 0) == 0 for e in events)
                else:
                    assert all(b'PROTECTED' in body for body in bodies[-4:])
                assert any(e['event'] == 'optional_followed' for e in events) == (
                    strategy in ('resource_explorer', 'protocol_js_explorer',
                                 'agent_like_solver', 'late_resource_explorer'))
                results.append(dict(variant=variant, strategy=strategy, repetition=repetition + 1,
                    authorized=any(e['event'] == 'authorized' for e in events),
                    optional_followed=any(e['event'] == 'optional_followed' for e in events),
                    origin_dispatches=dispatched,
                    protected_bytes=sum(e.get('protected_bytes', 0) for e in events),
                    events=events))
    return {'browser': browser.version, 'repetitions': repetitions,
            'manual_chrome': {'status': 'pending_operator_control', 'samples': 0},
            'strategy_provenance': 'Scripted strategies; no live LLM inference', 'runs': results}


def save(artifact, path):
    path.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
