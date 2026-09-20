import json
import sqlite3
import asyncio
from dataclasses import replace

import httpx
import pytest

from gateway.app import create_app
from gateway.config import Settings
from gateway.dashboard import DashboardStore, evaluate_dashboard
from gateway.detection.signals import Signals
from gateway.policies.evaluator import Decision


@pytest.fixture
def database(tmp_path):
    path = str(tmp_path / 'dashboard.db')
    with sqlite3.connect(path) as connection:
        connection.executescript('''
          CREATE TABLE sites(id TEXT PRIMARY KEY, domain TEXT, origin_url TEXT, policy TEXT, last_seen TEXT);
          CREATE TABLE events(request_id TEXT PRIMARY KEY, site_id TEXT, timestamp TEXT, method TEXT,
            path TEXT, decision TEXT, reason_codes TEXT, signals TEXT);
        ''')
        connection.execute('INSERT INTO sites VALUES (?,?,?,?,NULL)', (
            'test-site', 'example.com', 'http://dashboard-origin.test',
            json.dumps({'strictness': 'balanced', 'routes': []})))
    return path


def test_configuration_and_event_persistence(database):
    store = DashboardStore(database)
    settings, policy = store.configuration(Settings())
    assert settings.origin_url == 'http://dashboard-origin.test'
    assert policy['strictness'] == 'balanced'
    store.record(request_id='r1', site_id='test-site', method='GET', path='/private',
                 decision='BLOCK', reasons=['missing_session'])
    with store.connect() as connection:
        row = connection.execute('SELECT * FROM events').fetchone()
        assert json.loads(row['reason_codes']) == ['missing_session']
        assert row['timestamp'].endswith('Z')
        assert connection.execute('SELECT last_seen FROM sites').fetchone()[0]


def test_route_rules_never_grant_unverified_access():
    policy = {'strictness': 'balanced', 'routes': [{'pattern': '/api/*', 'action': 'verified'}]}
    signals = Signals(request={'html_navigation': True}, session={'valid': False})
    assert evaluate_dashboard(signals, policy, '/api/private')[0] == Decision.BLOCK
    assert evaluate_dashboard(signals, policy, '/products')[0] == Decision.CHALLENGE
    signals.session['valid'] = True
    assert evaluate_dashboard(signals, policy, '/api/private')[0] == Decision.ALLOW
    signals.session['invalid_token'] = True
    assert evaluate_dashboard(signals, policy, '/api/private')[0] == Decision.BLOCK


def test_block_rules_and_strictness_preserve_multiple_signal_requirement():
    signals = Signals(request={'html_navigation': True}, session={'valid': True}, browser={'webdriver': True})
    strict = {'strictness': 'strict', 'routes': []}
    assert evaluate_dashboard(signals, strict, '/')[0] == Decision.ALLOW
    signals.request['header_inconsistent'] = True
    assert evaluate_dashboard(signals, strict, '/')[0] == Decision.BLOCK
    policy = {'strictness': 'balanced', 'routes': [{'pattern': '/private', 'action': 'block'}]}
    assert evaluate_dashboard(Signals(session={'valid': True}), policy, '/private')[0] == Decision.BLOCK


def test_live_configuration_changes_and_database_failure(database):
    asyncio.run(check_live_configuration(database))


async def check_live_configuration(database):
    seen = []
    async def origin(request):
        seen.append(str(request.url))
        return httpx.Response(200, text='protected')
    async with httpx.AsyncClient(transport=httpx.MockTransport(origin)) as upstream:
        app = create_app(replace(Settings(), dashboard_db=database, origin_secret='a' * 32), upstream)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gateway.test') as client:
            headers = {'x-gateway-access-token': 'test-token'}
            assert (await client.get('/private', headers=headers)).status_code == 200
            assert seen == ['http://dashboard-origin.test/private']
            with sqlite3.connect(database) as connection:
                connection.execute('UPDATE sites SET policy = ?', (json.dumps({'strictness':'balanced','routes':[{'pattern':'/private','action':'block'}]}),))
            blocked = await client.get('/private', headers=headers)
            assert blocked.status_code == 403 and not blocked.content
            assert len(seen) == 1
            with sqlite3.connect(database) as connection:
                assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
                connection.execute('DELETE FROM sites')
            unavailable = await client.get('/private', headers=headers)
            assert unavailable.status_code == 503 and not unavailable.content
            assert len(seen) == 1
