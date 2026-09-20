"""Container entrypoint with explicit database bootstrap and conservative proxy trust."""
import os
from pathlib import Path

import uvicorn

from gateway.config import Settings
from gateway.database import initialize


def main():
    settings = Settings.from_env()
    settings.validate()
    # Railway volumes are initially root-owned. If the platform starts this
    # image as root, prepare only the fixed data directory, then drop privileges.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        if Path(settings.dashboard_db).resolve().parent != Path('/data'):
            raise ValueError('Root bootstrap only supports a database directly under /data')
        os.chown('/data', 10001, 10001)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    domain = os.environ['GATEWAY_DOMAIN']
    initialize(settings.dashboard_db, settings.site_id, domain, settings.origin_url)
    uvicorn.run('gateway.app:app', host='0.0.0.0', port=int(os.getenv('PORT', '8000')),
                workers=int(os.getenv('WEB_CONCURRENCY', '2')),
                proxy_headers=False, limit_concurrency=100, timeout_keep_alive=5)


if __name__ == '__main__':
    main()
