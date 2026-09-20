import secrets
import time
from threading import RLock
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from gateway.challenges.experiments import AgentExperiment, create_experiments


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
    trap_expires_at: float = 0
    trap_replays: int = 0
    verification_started: bool = False
    trap_phase: str | None = None
    event_count: int = 0
    events: list = field(default_factory=list)
    experiments: list[AgentExperiment] = field(default_factory=list)
    browser_report_supplied: bool = False


class EvidenceStore:
    """Bounded worker-local evidence; no raw IP, User-Agent, or page bodies."""
    def __init__(self, ttl=600, capacity=10000, clock=time.monotonic):
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self.records = OrderedDict()
        self.lock = RLock()

    def create(self, session_id):
        now = self.clock()
        while self.records:
            key = next(iter(self.records))
            if len(self.records) < self.capacity and self.records[key].expires_at > now:
                break
            self.records.popitem(last=False)
        record = Evidence(expires_at=now + self.ttl, created_at=now,
                          trap_expires_at=now + min(300, self.ttl))
        self.append_event(record, "challenge_issued")
        self.records[session_id] = record
        return record

    def update(self, session_id, operation):
        with self.lock:
            record = self.get(session_id)
            return operation(record) if record else None

    def append_event(self, record, kind, family=None):
        record.event_count += 1
        record.events.append({"order": record.event_count, "event": kind,
                              "elapsed_ms": max(0, int((self.clock() - record.created_at) * 1000))})
        if family:
            record.events[-1]["family"] = family
        del record.events[:-64]

    @staticmethod
    def interaction_signals(record):
        return {
            "tripwires": {"activated": bool(record.tripwire_hits),
                          "activation_phase": record.trap_phase,
                          "replays": record.trap_replays,
                          "experiments": [experiment.observation() for experiment in record.experiments]},
            "behavior": {"interaction_sequence": [dict(event) for event in record.events],
                         "sequence_truncated": record.event_count > len(record.events)},
        }

    def lifecycle(self, session_id, kind):
        def apply(record):
            if kind == "verification_submitted":
                record.verification_started = True
            self.append_event(record, kind)
            return self.interaction_signals(record)
        return self.update(session_id, apply)

    def expose_experiments(self, session_id, challenge_id):
        def apply(record):
            if not record.experiments:
                record.experiments = create_experiments(
                    challenge_id, session_id, record.created_at, record.trap_expires_at,
                    resource_id=record.tripwire_id)
                for experiment in record.experiments:
                    self.append_event(record, "experiment_exposed", experiment.experiment_type)
            return [experiment.descriptor() for experiment in record.experiments], self.interaction_signals(record)
        return self.update(session_id, apply)

    def activate_experiment(self, session_id, resource_id, method, *, legacy=False):
        def apply(record):
            experiment = next((item for item in record.experiments if secrets.compare_digest(
                item.resource_id.encode(), resource_id.encode()) and
                (not legacy or item.experiment_type == "resource")), None)
            if (not experiment or experiment.session_id != session_id or
                    self.clock() >= min(experiment.expires_at, record.trap_expires_at)):
                return 404, None
            if method != experiment.method:
                return 405, None
            if experiment.activated:
                experiment.replay_count = min(experiment.replay_count + 1, 100)
                record.trap_replays = min(record.trap_replays + 1, 100)
                self.append_event(record, "experiment_replay", experiment.experiment_type)
                return 410, self.interaction_signals(record)
            experiment.activated = True
            experiment.activation_phase = ("after_verification_started" if record.verification_started
                                           else "before_verification")
            self.append_event(record, "experiment_activated", experiment.experiment_type)
            experiment.activation_order = record.event_count
            record.tripwire_hits += 1
            if record.trap_phase is None:
                record.trap_phase = experiment.activation_phase
            return 204, self.interaction_signals(record)
        return self.update(session_id, apply) or (404, None)

    def activate(self, session_id, trap_id):
        """Consume a bound trap once; replay is evidence, never another risk group."""
        record = self.get(session_id)
        if record and record.experiments:
            return self.activate_experiment(session_id, trap_id, "GET", legacy=True)
        def apply(record):
            if (self.clock() >= record.trap_expires_at or not secrets.compare_digest(
                    record.tripwire_id.encode(), trap_id.encode())):
                return 404, None
            if record.tripwire_hits:
                record.trap_replays = min(record.trap_replays + 1, 100)
                self.append_event(record, "trap_replay")
                return 410, self.interaction_signals(record)
            record.tripwire_hits = 1
            record.trap_phase = ("after_verification_started" if record.verification_started
                                 else "before_verification")
            self.append_event(record, "trap_activated")
            return 204, self.interaction_signals(record)
        return self.update(session_id, apply) or (404, None)

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

    def hit(self, session_id):
        record = self.get(session_id)
        if record:
            record.tripwire_hits = min(record.tripwire_hits + 1, 100)

    def failure(self, session_id):
        record = self.get(session_id)
        if record:
            record.verification_failures = min(record.verification_failures + 1, 100)

    def report(self, session_id, browser):
        record = self.get(session_id)
        if record:
            record.browser_report_supplied = browser is not None
            record.browser = browser or {}
            record.verification_ms = max(0, int((self.clock() - record.created_at) * 1000))
