"""Site-scoped Redis security state. Expiry is enforced by Redis, not worker clocks."""
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
import json
import time

from redis.exceptions import WatchError

from gateway.challenges.store import InMemoryChallengeStore, ChallengeRecord, ChallengeStatus
from gateway.challenges.experiments import AgentExperiment
from gateway.detection.store import Evidence, EvidenceStore


class RedisSessions:
    def __init__(self, client, site_id):
        self.client, self.site_id = client, site_id
        self.prefix = f"stopin:{site_id}:session:"

    def issue(self, session_id, site_id, lifetime_seconds):
        if site_id != self.site_id:
            raise ValueError("Wrong site")
        self.client.set(self.prefix + session_id, '1', ex=lifetime_seconds)

    def valid(self, session_id, site_id):
        return site_id == self.site_id and bool(self.client.exists(self.prefix + session_id))

    def revoke(self, session_id, site_id):
        if site_id != self.site_id:
            raise ValueError("Wrong site")
        self.client.delete(self.prefix + session_id)


class RedisChallenges:
    # A wrong browser cannot burn another browser's challenge. Once the bound
    # browser attempts verification, GET+DELETE is atomic even across workers.
    CONSUME = """
    local raw = redis.call('GET', KEYS[1])
    if not raw then return false end
    local record = cjson.decode(raw)
    if record.session_id ~= ARGV[1] then return false end
    redis.call('DEL', KEYS[1])
    return raw
    """

    def __init__(self, client, site_id):
        self.client = client
        self.prefix = f"stopin:{site_id}:challenge:"

    def create(self, *, session_id, ttl_seconds=300, now=None):
        record = InMemoryChallengeStore().create(session_id=session_id, ttl_seconds=ttl_seconds, now=now)
        self.client.set(self.prefix + record.challenge_id, json.dumps(record.to_dict()), ex=ttl_seconds)
        return record

    @staticmethod
    def decode(raw):
        if not raw:
            return None
        data = json.loads(raw)
        for field in ('created_at', 'expires_at'):
            data[field] = datetime.fromisoformat(data[field])
        data['status'] = ChallengeStatus(data['status'])
        return ChallengeRecord(**data)

    def get(self, challenge_id):
        return self.decode(self.client.get(self.prefix + challenge_id))

    def verify(self, *, challenge_id, session_id, nonce, now=None):
        import secrets
        raw = self.client.eval(self.CONSUME, 1, self.prefix + challenge_id, session_id)
        record = self.decode(raw)
        return bool(record and record.expires_at > (now or datetime.now(timezone.utc))
                    and secrets.compare_digest(record.nonce.encode(), nonce.encode()))


class RedisEvidence(EvidenceStore):
    def __init__(self, client, site_id):
        super().__init__(clock=time.time)
        self.client = client
        self.prefix = f"stopin:{site_id}:evidence:"

    @staticmethod
    def encode(record):
        data = asdict(record)
        data['requests'] = list(record.requests)
        return json.dumps(data)

    @staticmethod
    def decode(raw, session_id):
        if not raw:
            return None
        data = json.loads(raw)
        data['requests'] = deque(data['requests'], maxlen=101)
        data['experiments'] = [AgentExperiment(**item) for item in data.get('experiments', [])]
        record = Evidence(**data)
        record._session_id = session_id
        return record

    def create(self, session_id):
        now = self.clock()
        record = Evidence(expires_at=now + self.ttl, created_at=now,
                          trap_expires_at=now + min(300, self.ttl))
        self.append_event(record, "challenge_issued")
        record._session_id = session_id
        self.client.set(self.prefix + session_id, self.encode(record), ex=self.ttl)
        return record

    def get(self, session_id):
        return self.decode(self.client.get(self.prefix + session_id), session_id) if session_id else None

    def update(self, session_id, operation):
        if not session_id:
            return None
        key = self.prefix + session_id
        for _ in range(10):
            with self.client.pipeline() as pipe:
                try:
                    pipe.watch(key)
                    record = self.decode(pipe.get(key), session_id)
                    if record is None:
                        return None
                    result = operation(record)
                    pipe.multi()
                    pipe.set(key, self.encode(record), keepttl=True)
                    pipe.execute()
                    return result
                except WatchError:
                    continue
        from redis.exceptions import RedisError
        raise RedisError("Evidence contention limit exceeded")

    def observe(self, record, category):
        return self.update(record._session_id, lambda fresh: super(RedisEvidence, self).observe(fresh, category)) or (0, None)

    def hit(self, session_id):
        self.update(session_id, lambda r: setattr(r, 'tripwire_hits', min(r.tripwire_hits + 1, 100)))

    def failure(self, session_id):
        self.update(session_id, lambda r: setattr(r, 'verification_failures', min(r.verification_failures + 1, 100)))

    def report(self, session_id, browser):
        def apply(record):
            record.browser_report_supplied = browser is not None
            record.browser = browser or {}
            record.verification_ms = max(0, int((self.clock() - record.created_at) * 1000))
        self.update(session_id, apply)
