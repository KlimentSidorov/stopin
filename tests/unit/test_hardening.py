from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.database import initialize, backup, prune
from gateway.distributed import RedisChallenges, RedisSessions, RedisEvidence
from gateway.hardening import RequestControls
from gateway.sessions.tokens import create_access_token, verify_access_token


@pytest.fixture
def shared():
    return fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)


def settings(**overrides):
    return replace(Settings(dev_access_token='', origin_secret='o' * 32), **overrides)


def client(shared, **overrides):
    origin = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text='protected')))
    return TestClient(create_app(settings(**overrides), origin, shared))


def test_atomic_consumption_and_wrong_browser(shared):
    a, b = RedisChallenges(shared, 'a'), RedisChallenges(shared, 'a')
    record = a.create(session_id='browser')
    args = dict(challenge_id=record.challenge_id, session_id='browser', nonce=record.nonce)
    assert not b.verify(**{**args, 'session_id': 'attacker'})
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: b.verify(**args), range(16)))
    assert sum(outcomes) == 1
    record = a.create(session_id='browser')
    args['challenge_id'] = record.challenge_id
    assert not a.verify(**args)  # Wrong nonce burns the bound browser's attempt.
    assert not a.verify(**{**args, 'nonce': record.nonce})


def test_shared_sessions_revocation_expiry_and_tenant_boundary(shared):
    a, b = RedisSessions(shared, 'a'), RedisSessions(shared, 'a')
    other = RedisSessions(shared, 'b')
    a.issue('session', 'a', 300)
    assert b.valid('session', 'a')
    assert not other.valid('session', 'a')
    assert not other.valid('session', 'b')
    with pytest.raises(ValueError):
        other.revoke('session', 'a')
    b.revoke('session', 'a')
    assert not a.valid('session', 'a')
    a.issue('session', 'a', 300)
    shared.expire(a.prefix + 'session', 0)
    assert not b.valid('session', 'a')


def test_evidence_shared_updates_and_expiry(shared):
    a, b = RedisEvidence(shared, 'a'), RedisEvidence(shared, 'a')
    a.create('browser')
    stale = a.get('browser')
    b.hit('browser')
    a.observe(stale, 'api')
    b.failure('browser')
    a.report('browser', {'webdriver': True})
    current = b.get('browser')
    assert current.tripwire_hits == current.verification_failures == 1
    assert current.browser == {'webdriver': True}
    assert len(current.requests) == 1
    assert RedisEvidence(shared, 'b').get('browser') is None
    assert 0 < shared.ttl(a.prefix + 'browser') <= 600


def test_challenge_cross_worker_and_cross_site_cookie_rejection(shared):
    with client(shared) as a, client(shared) as b, client(shared, site_id='other') as other:
        challenge = a.post('/challenge').json()
        b.cookies.update(a.cookies)
        payload = {key: challenge[key] for key in ('challenge_id', 'session_id', 'nonce')}
        assert b.post('/challenge/verify', json=payload).status_code == 200
        a.cookies.update(b.cookies)
        assert a.get('/private').text == 'protected'
        other.cookies.update(b.cookies)
        assert other.get('/private').status_code == 403
        b.app.state.session_store.revoke(challenge['session_id'], 'test-site')
        assert a.get('/private').status_code == 403


def test_distributed_rate_limits_ignore_forwarded_headers(shared):
    with client(shared, challenge_rate_limit=2) as a, client(shared, challenge_rate_limit=2) as b:
        assert a.post('/challenge').status_code == 200
        assert b.post('/challenge').status_code == 200
        response = a.post('/challenge', headers={'x-forwarded-for': '1.2.3.4'})
        assert response.status_code == 429
        assert int(response.headers['retry-after']) > 0
    isolated = RequestControls(settings(site_id='other', challenge_rate_limit=2), shared)
    assert isolated.allow('testclient', True)[0]


def test_outage_fails_closed_and_readiness_differs_from_liveness(shared):
    with client(shared) as a:
        a.app.state.controls.redis.connection_pool.connection_kwargs['server'].connected = False
        assert a.get('/health').status_code == 200
        assert a.get('/ready').status_code == 503
        assert a.get('/private').status_code == 503


def test_metrics_auth_aggregation_body_limit_and_hosts(shared):
    options = dict(metrics_token='m' * 32, max_body_bytes=10, allowed_hosts=('testserver',))
    with client(shared, **options) as a, client(shared, **options) as b:
        assert a.get('/metrics').status_code == 403
        assert a.get('/private').status_code == 403
        assert b.post('/private', content=b'x' * 11).status_code == 413
        response = b.get('/metrics', headers={'Authorization': 'Bearer ' + 'm' * 32})
        assert response.status_code == 200
        assert 'status="4xx"} 2' in response.text
        assert '/private' not in response.text
        assert b.get('/health', headers={'Host': 'evil.test'}).status_code == 400


def test_key_rotation_overlap_and_removal():
    token = create_access_token('session', 'old', site_id='a')
    assert verify_access_token(token, 'new', 'a', ('old',)) == 'session'
    assert verify_access_token(token, 'new', 'a') is None
    assert verify_access_token(token, 'new', 'b', ('old',)) is None
    assert verify_access_token('x' * 4097, 'new', 'a') is None


def test_production_configuration_rejects_unsafe_defaults():
    safe = settings(production=True, redis_url='redis://redis:6379', token_secret='s' * 32,
                    metrics_token='m' * 32, cookie_secure=True, allowed_hosts=('example.com',),
                    dashboard_db='configured.db')
    safe.validate()
    for change in ({'redis_url': ''}, {'dev_access_token': 'bypass'}, {'cookie_secure': False},
                   {'allowed_hosts': ('*',)}, {'token_secret': 'short'}, {'dashboard_db': ''}):
        with pytest.raises(ValueError):
            replace(safe, **change).validate()


def test_railway_proxy_requires_valid_edge_identity(shared):
    with client(shared, trust_railway_proxy=True, rate_limit=1) as a:
        assert a.get('/private').status_code == 400
        assert a.get('/private', headers={'x-real-ip': 'bad'}).status_code == 400
        assert a.get('/private', headers={'x-real-ip': '192.0.2.1'}).status_code == 403
        assert a.get('/private', headers={'x-real-ip': '192.0.2.1'}).status_code == 429
        assert a.get('/private', headers={'x-real-ip': '192.0.2.2'}).status_code == 403


def test_production_env_requires_explicit_key(monkeypatch):
    monkeypatch.setenv('GATEWAY_ENV', 'production')
    monkeypatch.delenv('GATEWAY_TOKEN_SECRET', raising=False)
    with pytest.raises(ValueError, match='explicit stable signing key'):
        Settings.from_env()


def test_database_migration_backup_and_site_scoped_retention(tmp_path):
    path, snapshot = tmp_path / 'db.sqlite', tmp_path / 'backup.sqlite'
    initialize(path, 'a', 'a.example', 'https://origin.example')
    initialize(path, 'a', 'a.example', 'https://origin.example')
    initialize(path, 'b', 'b.example', 'https://other.example')
    with sqlite3.connect(path) as db:
        for site in ('a', 'b'):
            db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)',
                       (site, site, '2000-01-01T00:00:00.000Z', 'GET', '/', 'BLOCK', '[]', '{}'))
    backup(path, snapshot)
    assert prune(path, 'a') == 1
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT site_id FROM events').fetchall() == [('b',)]
    with sqlite3.connect(snapshot) as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 2
    with pytest.raises(ValueError):
        backup(path, snapshot)
