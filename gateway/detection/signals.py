from dataclasses import asdict, dataclass, field

from pydantic import BaseModel, ConfigDict, Field


class BrowserReport(BaseModel):
    """Untrusted optional client observations; never proof of identity."""
    model_config = ConfigDict(strict=True, extra="forbid")
    javascript: bool = False
    webdriver: bool | None = None
    elapsed_ms: float = Field(default=0, ge=0, le=3600000, allow_inf_nan=False)


@dataclass
class Signals:
    request: dict = field(default_factory=dict)
    browser: dict = field(default_factory=dict)
    behavior: dict = field(default_factory=dict)
    tripwires: dict = field(default_factory=dict)
    rate: dict = field(default_factory=dict)
    crawler: dict = field(default_factory=lambda: {"identity": "unverified"})
    session: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
