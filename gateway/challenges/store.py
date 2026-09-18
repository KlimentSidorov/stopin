from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import secrets
from typing import Any


class ChallengeStatus(StrEnum):
    NEW = "NEW"
    ISSUED = "ISSUED"
    VERIFIED = "VERIFIED"
    CONSUMED = "CONSUMED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass(slots=True)
class ChallengeRecord:
    challenge_id: str
    nonce: str
    created_at: datetime
    expires_at: datetime
    status: ChallengeStatus
    session_id: str
    attempt_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "session_id": self.session_id,
            "attempt_count": self.attempt_count,
        }


class ChallengeStore:
    def create(self, *, session_id: str, ttl_seconds: int = 300, now: datetime | None = None) -> ChallengeRecord:
        raise NotImplementedError

    def verify(
        self,
        *,
        challenge_id: str,
        session_id: str,
        nonce: str,
        now: datetime | None = None,
    ) -> bool:
        raise NotImplementedError

    def get(self, challenge_id: str) -> ChallengeRecord | None:
        raise NotImplementedError


class InMemoryChallengeStore(ChallengeStore):
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._records: dict[str, ChallengeRecord] = {}

    def __repr__(self) -> str:
        return f"InMemoryChallengeStore(ttl_seconds={self.ttl_seconds}, challenge_count={len(self._records)})"

    def create(
        self,
        *,
        session_id: str,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> ChallengeRecord:
        if not session_id:
            raise ValueError("session_id is required")

        resolved_now = now or datetime.now(timezone.utc)
        resolved_ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        challenge = ChallengeRecord(
            challenge_id=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            created_at=resolved_now,
            expires_at=resolved_now + timedelta(seconds=resolved_ttl),
            status=ChallengeStatus.ISSUED,
            session_id=session_id,
        )
        self._records[challenge.challenge_id] = challenge
        return challenge

    def verify(
        self,
        *,
        challenge_id: str,
        session_id: str,
        nonce: str,
        now: datetime | None = None,
    ) -> bool:
        record = self._records.get(challenge_id)
        if record is None:
            return False

        resolved_now = now or datetime.now(timezone.utc)
        if record.session_id != session_id:
            return False

        if record.expires_at <= resolved_now:
            record.status = ChallengeStatus.EXPIRED
            return False

        if record.status in {ChallengeStatus.CONSUMED, ChallengeStatus.FAILED, ChallengeStatus.EXPIRED}:
            return False

        if record.nonce != nonce:
            record.status = ChallengeStatus.FAILED
            record.attempt_count += 1
            return False

        record.attempt_count += 1
        record.status = ChallengeStatus.CONSUMED
        return True

    def get(self, challenge_id: str) -> ChallengeRecord | None:
        return self._records.get(challenge_id)


_DEFAULT_STORE = InMemoryChallengeStore()
