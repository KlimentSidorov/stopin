from __future__ import annotations

from datetime import datetime

from gateway.challenges.store import ChallengeRecord, InMemoryChallengeStore, _DEFAULT_STORE


def create_challenge(
    *,
    session_id: str,
    store: InMemoryChallengeStore | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> ChallengeRecord:
    challenge_store = store or _DEFAULT_STORE
    return challenge_store.create(session_id=session_id, ttl_seconds=ttl_seconds, now=now)
