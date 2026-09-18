import time


class InMemorySessionStore:
    """Verified sessions for this worker; restarting revokes all access."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str], float] = {}

    def issue(self, session_id: str, site_id: str, lifetime_seconds: int) -> None:
        self._sessions[(site_id, session_id)] = time.time() + lifetime_seconds

    def valid(self, session_id: str, site_id: str) -> bool:
        key = (site_id, session_id)
        if self._sessions.get(key, 0) <= time.time():
            self._sessions.pop(key, None)
            return False
        return True

    def revoke(self, session_id: str, site_id: str) -> None:
        self._sessions.pop((site_id, session_id), None)
