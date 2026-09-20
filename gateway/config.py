from dataclasses import dataclass, field
import os
import secrets
import json
import re


@dataclass(frozen=True)
class Settings:
    origin_url: str = "http://origin.test"
    site_id: str = "test-site"
    dev_access_token: str = "test-token"

    # Fake secret used ONLY during automated tests.
    # We don't use the real .env secret in unit tests.
    token_secret: str = field(default="test-secret", repr=False)

    timeout_seconds: float = 5.0
    cookie_secure: bool = False
    origin_secret: str = field(default="", repr=False)
    dashboard_db: str = ""
    production: bool = False
    redis_url: str = field(default="", repr=False)
    token_previous_secrets: tuple[str, ...] = field(default=(), repr=False)
    allowed_hosts: tuple[str, ...] = ()
    metrics_token: str = field(default="", repr=False)
    rate_limit: int = 120
    challenge_rate_limit: int = 20
    max_body_bytes: int = 1048576
    trust_railway_proxy: bool = False

    def validate(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.site_id):
            raise ValueError("Site ID must contain 1-64 letters, digits, underscores or hyphens")
        if min(self.rate_limit, self.challenge_rate_limit, self.max_body_bytes) < 1:
            raise ValueError("Request limits must be positive")
        if not isinstance(self.token_previous_secrets, tuple) or any(not isinstance(key, str) or not key for key in self.token_previous_secrets):
            raise ValueError("Previous signing keys must be a list of nonempty strings")
        if len(self.token_previous_secrets) > 2:
            raise ValueError("At most two previous signing keys are supported")
        if self.production:
            from gateway.origin.protection import validate_secret
            from urllib.parse import urlsplit
            validate_secret(self.origin_secret)
            if any(len(key) < 32 for key in (self.token_secret, self.metrics_token, *self.token_previous_secrets)):
                raise ValueError("Production signing and metrics keys must have at least 32 characters")
            if self.dev_access_token or not self.cookie_secure or not self.redis_url:
                raise ValueError("Production requires Redis, secure cookies and no development bypass")
            if not self.allowed_hosts or any('*' in host for host in self.allowed_hosts):
                raise ValueError("Production requires explicit allowed hosts")
            if not self.dashboard_db:
                raise ValueError("Production requires a configured database")
            if urlsplit(self.origin_url).scheme not in ('http', 'https'):
                raise ValueError("Invalid origin URL")

    @classmethod
    def from_env(cls) -> "Settings":
        production = os.getenv("GATEWAY_ENV", "development") == "production"
        if production and not os.getenv("GATEWAY_TOKEN_SECRET"):
            raise ValueError("Production requires an explicit stable signing key")
        previous = json.loads(os.getenv("GATEWAY_TOKEN_PREVIOUS_SECRETS", "[]"))
        if not isinstance(previous, list):
            raise ValueError("GATEWAY_TOKEN_PREVIOUS_SECRETS must be a JSON list")
        return cls(
            production=production,
            trust_railway_proxy=os.getenv("GATEWAY_TRUST_RAILWAY_PROXY", "false").lower() == "true",
            redis_url=os.getenv("GATEWAY_REDIS_URL", ""),
            token_previous_secrets=tuple(previous),
            allowed_hosts=tuple(h.strip() for h in os.getenv("GATEWAY_ALLOWED_HOSTS", "").split(',') if h.strip()),
            metrics_token=os.getenv("GATEWAY_METRICS_TOKEN", ""),
            rate_limit=int(os.getenv("GATEWAY_RATE_LIMIT", "120")),
            challenge_rate_limit=int(os.getenv("GATEWAY_CHALLENGE_RATE_LIMIT", "20")),
            max_body_bytes=int(os.getenv("GATEWAY_MAX_BODY_BYTES", "1048576")),
            dashboard_db=os.getenv("GATEWAY_DASHBOARD_DB", ""),
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
            origin_secret=os.getenv("GATEWAY_ORIGIN_SECRET", ""),
            cookie_secure=os.getenv("GATEWAY_COOKIE_SECURE", "false").lower() == "true",
            timeout_seconds=float(
                os.getenv(
                    "GATEWAY_TIMEOUT_SECONDS",
                    "10",
                )
            ),
        )
