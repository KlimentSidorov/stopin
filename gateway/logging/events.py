import json
import logging
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger("gateway.events")


def record_decision(
    *,
    request_id: str,
    site_id: str,
    method: str,
    path: str,
    decision: str,
    reasons: list[str],
) -> None:
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "site_id": site_id,
        "method": method,
        "path": path,
        "decision": decision,
        "reason_codes": reasons,
    }
    logger.info(json.dumps(event, separators=(",", ":")))
