import secrets
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field


@dataclass
class Evidence:
    expires_at: float
    tripwire_id: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    tripwire_hits: int = 0
    requests: deque = field(default_factory=lambda: deque(maxlen=101))
    browser: dict = field(default_factory=dict)
    verification_ms: int | None = None
    verification_failures: int = 0
    last_category: str | None = None
    created_at: float = field(default_factory=time.monotonic)


class EvidenceStore:
    """Bounded worker-local evidence; no raw IP, User-Agent, or page bodies."""
    def __init__(self, ttl=600, capacity=10000, clock=time.monotonic):
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self.records = OrderedDict()

    def create(self, session_id):
        now = self.clock()
        while self.records:
            key = next(iter(self.records))
            if len(self.records) < self.capacity and self.records[key].expires_at > now:
                break
            self.records.popitem(last=False)
        record = Evidence(expires_at=now + self.ttl, created_at=now)
        self.records[session_id] = record
        return record

    def get(self, session_id):
        record = self.records.get(session_id)
        if record and record.expires_at <= self.clock():
            self.records.pop(session_id, None)
            return None
        return record

    def observe(self, record, category):
        now = self.clock()
        while record.requests and record.requests[0] <= now - 10:
            record.requests.popleft()
        record.requests.append(now)
        previous = record.last_category
        record.last_category = category
        return len(record.requests), previous
