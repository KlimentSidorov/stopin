import importlib.util
import asyncio
import re
from pathlib import Path

import httpx
import pytest

from conftest import serve
from gateway.pre_application import create_lab


def test_pre_application_strategy_matrix(chromium, tmp_path):
    calls = []

    def fixture(request):
        calls.append(request.url.path)
        return httpx.Response(200, text='PROTECTED-LAB-CONTENT ' + request.url.path)

    origin = httpx.AsyncClient(transport=httpx.MockTransport(fixture), base_url='http://origin')
    app = create_lab(origin)
    source = Path(__file__).resolve().parents[2] / 'test-agents' / 'pre_application_matrix.py'
    spec = importlib.util.spec_from_file_location('pre_application_matrix', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with serve(app) as url:
        artifact = module.collect(chromium, url, app, calls)
    path = tmp_path / 'pre-application-agent-trap-results.json'
    module.save(artifact, path)
    print('PRE_APPLICATION_RESULTS_FILE ' + str(path))
    # The aware control follows exactly the same automatic path as normal Playwright.
    def trace(run):
        return [(e['event'], e.get('route'), e.get('method'), e.get('status'))
                for e in run['events']]
    for variant in module.VARIANTS:
        normal = next(r for r in artifact['runs'] if r['variant'] == variant
                      and r['strategy'] == 'normal_playwright')
        aware = next(r for r in artifact['runs'] if r['variant'] == variant
                     and r['strategy'] == 'stopin_aware_minimal')
        assert trace(normal) == trace(aware)


@pytest.mark.parametrize('variant', ('comment', 'inert_manifest', 'dormant_function'))
def test_pre_application_real_nextjs_boundary(nextjs_origin, variant):
    dispatches = []

    async def observe(request):
        dispatches.append(request.url.path)

    upstream = httpx.AsyncClient(base_url=nextjs_origin.url,
        limits=httpx.Limits(max_keepalive_connections=0),
        headers={'X-Gateway-Origin-Secret': nextjs_origin.secret},
        event_hooks={'request': [observe]})
    app = create_lab(upstream)
    with serve(app) as url, httpx.Client(base_url=url) as client:
        for path in ('/private', '/api/private', '/_next/data/lab/private.json',
                     '/_next/static/lab.js', '/private.txt', '/private?_rsc=1'):
            assert client.get(path).content == b''
        html = client.get('/start', params={'variant': variant}).text
        script = client.get(re.search(r'src="([^"]+)"', html)[1]).text
        assert nextjs_origin.secret not in html + script
        assert 'NEXTJS-PROTECTED-ORIGIN-CONTENT' not in html + script
        assert not dispatches
        trap = re.search(r'/__trap/optional/[A-Za-z0-9_-]+', html + script)[0]
        complete = re.search(r'/__trap/complete/[A-Za-z0-9_-]+', script)[0]
        assert client.get(trap).status_code == 403
        assert client.post(complete).status_code == 403
        for path in ('/private', '/api/private', '/_next/data/lab/private.json',
                     '/_next/static/lab.js', '/private?_rsc=1'):
            assert client.get(path).content == b''
        assert not dispatches
        # Fresh-session retry is an additional deliberate bypass.
        html = client.get('/start', params={'variant': variant}).text
        script = client.get(re.search(r'src="([^"]+)"', html)[1]).text
        complete = re.search(r'/__trap/complete/[A-Za-z0-9_-]+', script)[0]
        assert client.post(complete).status_code == 204
        for path in ('/private', '/api/private'):
            response = client.get(path)
            assert 'NEXTJS-PROTECTED-ORIGIN-CONTENT' in response.text
            assert nextjs_origin.secret not in response.text
        assert dispatches == ['/private', '/api/private']
    # The live server's loop has stopped; close is safe with keep-alives disabled below.
    asyncio.run(upstream.aclose())
