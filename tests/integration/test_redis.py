"""Real Redis integration. CI supplies a disposable service; local runs opt in."""
import os
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

import pytest
from redis import Redis

from gateway.distributed import RedisChallenges, RedisSessions, RedisEvidence
from gateway.config import Settings
from gateway.hardening import RequestControls


@pytest.mark.skipif(not os.getenv('TEST_REDIS_URL'), reason='TEST_REDIS_URL not configured')
def test_real_redis_atomicity_and_shared_state():
    site = 'ci_' + uuid4().hex
    a = Redis.from_url(os.environ['TEST_REDIS_URL'], decode_responses=True)
    b = Redis.from_url(os.environ['TEST_REDIS_URL'], decode_responses=True)
    try:
        challenges = RedisChallenges(a, site)
        record = challenges.create(session_id='browser')
        args = dict(challenge_id=record.challenge_id, session_id='browser', nonce=record.nonce)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: RedisChallenges(b, site).verify(**args), range(16)))
        assert sum(results) == 1
        RedisSessions(a, site).issue('session', site, 60)
        assert RedisSessions(b, site).valid('session', site)
        RedisSessions(b, site).revoke('session', site)
        assert not RedisSessions(a, site).valid('session', site)
        evidence = RedisEvidence(a, site)
        evidence.create('session')
        RedisEvidence(b, site).hit('session')
        assert evidence.get('session').tripwire_hits == 1
        trap = evidence.create('agent-experiment')
        other_evidence = RedisEvidence(b, site)
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: other_evidence.activate(
                'agent-experiment', trap.tripwire_id)[0], range(8)))
        assert sorted(outcomes) == [204] + [410] * 7
        other_evidence.lifecycle('agent-experiment', 'verification_submitted')
        sequence = evidence.get('agent-experiment').events
        assert [event['order'] for event in sequence] == list(range(1, 11))
        assert sequence[-1]['event'] == 'verification_submitted'
        assert RedisEvidence(b, site + '_other').activate(
            'agent-experiment', trap.tripwire_id) == (404, None)
        evidence.create('adaptive-agent')
        descriptors, _ = evidence.expose_experiments('adaptive-agent', 'adaptive-challenge')
        for descriptor in descriptors:
            resource_id = descriptor['url'].rsplit('/', 1)[-1]
            with ThreadPoolExecutor(max_workers=4) as pool:
                outcomes = list(pool.map(lambda _: other_evidence.activate_experiment(
                    'adaptive-agent', resource_id, descriptor['method'])[0], range(8)))
            assert sorted(outcomes) == [204] + [410] * 7
            assert RedisEvidence(b, site + '_other').activate_experiment(
                'adaptive-agent', resource_id, descriptor['method']) == (404, None)
        adaptive = evidence.get('adaptive-agent')
        assert all(item.activated and item.replay_count == 7 for item in adaptive.experiments)
        assert [event['order'] for event in adaptive.events] == list(range(1, 29))
        controls = RequestControls(Settings(site_id=site, rate_limit=3), a)
        other = RequestControls(Settings(site_id=site, rate_limit=3), b)
        assert controls.allow('127.0.0.1')[0]
        assert other.allow('127.0.0.1')[0]
        assert controls.allow('127.0.0.1')[0]
        assert not other.allow('127.0.0.1')[0]
    finally:
        # Only delete this test's random namespace, never other application data.
        keys = list(a.scan_iter(match=f'stopin:{site}:*'))
        if keys:
            a.delete(*keys)
        a.close()
        b.close()
