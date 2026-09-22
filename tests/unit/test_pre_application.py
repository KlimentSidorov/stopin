import re

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.pre_application import COOKIE, VARIANTS, create_lab


@pytest.fixture
def lab():
    calls = []
    now = [100.0]

    def origin(request):
        calls.append(request.url.path)
        return httpx.Response(200, text="PROTECTED-SECRET")

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin), base_url="http://origin")
    app = create_lab(upstream, clock=lambda: now[0])
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1234)) as client:
        yield client, app, calls, now


def issue(client, variant="comment"):
    page = client.get("/start", params={"variant": variant})
    script_url = re.search(r'src="([^"]+)"', page.text)[1]
    script = client.get(script_url)
    complete = re.search(r"fetch\('([^']+)'", script.text)[1]
    return page, script, complete


@pytest.mark.parametrize("variant", VARIANTS)
def test_optional_is_bound_and_blocks_before_release(lab, variant):
    client, app, calls, _ = lab
    page, script, complete = issue(client, variant)
    run = next(iter(app.state.sessions.values()))
    trap = "/__trap/optional/" + run["optional"]
    assert trap in page.text + script.text
    assert "PROTECTED-SECRET" not in page.text + script.text
    assert calls == []
    assert client.get(trap).status_code == 403
    assert client.post(complete).status_code == 403
    for path in ("/private", "/api/private", "/_next/data/lab/private.json",
                 "/_next/static/lab.js", "/private.txt", "/challenge", "/health"):
        response = client.get(path)
        assert response.status_code == 403 and not response.content
    assert calls == []
    assert all(e.get("protected_bytes", 0) == 0 for e in app.state.events)


def test_replay_expiry_cross_session_and_forgery(lab):
    client, app, calls, now = lab
    _, _, old_complete = issue(client)
    first = next(iter(app.state.sessions.values()))
    _, _, complete = issue(client)
    assert client.post(old_complete).status_code == 403
    assert client.get('/__trap/optional/' + first['optional']).status_code == 403
    assert client.post(complete + 'forged').status_code == 403
    assert client.get('/private', headers={'Authorization': 'Bearer forged'}).status_code == 403
    assert not calls
    assert client.post(complete).status_code == 204
    assert client.post(complete).status_code == 403
    assert client.get('/private').text == 'PROTECTED-SECRET'
    now[0] += 91
    assert client.get('/api/private').status_code == 403
    assert calls == ['/private']
    client.cookies.clear()
    client.cookies.set(COOKIE, 'forged')
    assert client.post(complete).status_code == 403


def test_minimal_protocol_bypass_needs_no_javascript(lab):
    client, app, calls, _ = lab
    _, _, complete = issue(client)
    assert not calls
    assert client.post(complete).status_code == 204
    for path in ('/private', '/api/private', '/_next/data/lab/private.json', '/_next/static/lab.js'):
        assert client.get(path).text == 'PROTECTED-SECRET'
    events = app.state.events
    assert next(e['order'] for e in events if e['event'] == 'authorized') < next(
        e['order'] for e in events if e['event'] == 'origin_dispatch')


def test_late_exploration_cannot_retract_released_content(lab):
    client, app, calls, _ = lab
    _, _, complete = issue(client)
    client.post(complete)
    assert client.get('/private').text == 'PROTECTED-SECRET'
    run = next(iter(app.state.sessions.values()))
    client.get('/__trap/optional/' + run['optional'])
    assert client.get('/api/private').status_code == 403
    assert calls == ['/private']  # Explicit counterexample to retrospective zero release.


def test_no_authorization_via_alternate_methods_or_paths(lab):
    client, app, calls, _ = lab
    _, _, complete = issue(client)
    for method in ('GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE'):
        assert client.request(method, complete).status_code == 403
    for path in ('/api/private', '/_next/data/lab/private.json', '/_next/static/lab.js',
                 '/private?authorized=true', '/%70rivate', '/__trap/optional/forged'):
        assert client.get(path).status_code == 403
    assert not calls


def test_randomization_and_local_boundary(lab):
    client, app, calls, _ = lab
    issue(client)
    issue(client)
    first, second = app.state.sessions.values()
    assert first['capability'] != second['capability']
    assert first['optional'] != second['optional']
    assert client.get('/start', headers={'host': 'external.example'}).status_code == 403
    assert not calls
