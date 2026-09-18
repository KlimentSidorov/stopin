from __future__ import annotations

from datetime import datetime

from gateway.challenges.store import ChallengeStore, InMemoryChallengeStore, _DEFAULT_STORE


def verify_challenge(
    challenge_id: str,
    session_id: str,
    nonce: str,
    *,
    store: ChallengeStore | None = None,
    now: datetime | None = None,
) -> bool:
    if not challenge_id or not session_id or not nonce:
        return False

    challenge_store = store or _DEFAULT_STORE
    return challenge_store.verify(
        challenge_id=challenge_id,
        session_id=session_id,
        nonce=nonce,
        now=now,
    )
