import time

from gateway.sessions.tokens import (
    create_access_token,
    verify_access_token,
)


SECRET = "my-test-server-secret"


def test_valid_token() -> None:
    token = create_access_token(
        session_id="session-123",
        secret=SECRET,
    )

    session_id = verify_access_token(
        token,
        SECRET,
    )

    assert session_id == "session-123"


def test_modified_signature_is_rejected() -> None:
    token = create_access_token(
        session_id="session-123",
        secret=SECRET,
    )

    # Damage the signature.
    payload, signature = token.split(".", 1)

    forged_token = payload + "." + ("0" * len(signature))

    assert verify_access_token(
        forged_token,
        SECRET,
    ) is None


def test_wrong_secret_is_rejected() -> None:
    token = create_access_token(
        session_id="session-123",
        secret=SECRET,
    )

    assert verify_access_token(
        token,
        "attacker-secret",
    ) is None


def test_expired_token_is_rejected() -> None:
    token = create_access_token(
        session_id="session-123",
        secret=SECRET,
        lifetime_seconds=1,
    )

    time.sleep(1.1)

    assert verify_access_token(
        token,
        SECRET,
    ) is None