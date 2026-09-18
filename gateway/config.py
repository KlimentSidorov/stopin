from dataclasses import dataclass
import os
import secrets


@dataclass(frozen=True)
class Settings:
    origin_url: str = "http://origin.test"
    site_id: str = "test-site"
    dev_access_token: str = "test-token"

    # Fake secret used ONLY during automated tests.
    # We don't use the real .env secret in unit tests.
    token_secret: str = "test-secret"

    timeout_seconds: float = 5.0
    cookie_secure: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            origin_url=os.getenv(
                "GATEWAY_ORIGIN_URL",
                "http://localhost:3000",
            ).rstrip("/"),
            site_id=os.getenv(
                "GATEWAY_SITE_ID",
                "local",
            ),
            dev_access_token=os.getenv(
                "GATEWAY_DEV_ACCESS_TOKEN",
                "",
            ),
            token_secret=os.getenv(
                "GATEWAY_TOKEN_SECRET",
                secrets.token_urlsafe(32),
            ),
            cookie_secure=os.getenv("GATEWAY_COOKIE_SECURE", "false").lower() == "true",
            timeout_seconds=float(
                os.getenv(
                    "GATEWAY_TIMEOUT_SECONDS",
                    "10",
                )
            ),
        )
