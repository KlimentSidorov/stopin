"""Optional local dashboard bridge. SQLite config is operator-controlled, not request input."""
import json
import logging
import sqlite3
import re
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone

from gateway.policies.evaluator import Decision, evaluate_signals

logger = logging.getLogger(__name__)


class DashboardStore:
    def __init__(self, path: str):
        self.path = path

    @contextmanager
    def connect(self):
        # Do not silently create an empty database if the configured path is wrong.
        from pathlib import Path
        connection = sqlite3.connect(Path(self.path).resolve().as_uri() + '?mode=rw', uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def configuration(self, settings):
        with self.connect() as connection:
            row = connection.execute('SELECT * FROM sites WHERE id = ?', (settings.site_id,)).fetchone()
        if row is None:
            raise ValueError('Dashboard site is not configured')
        policy = json.loads(row['policy'])
        if not isinstance(policy, dict) or policy.get('strictness') not in ('balanced', 'strict') or not isinstance(policy.get('routes'), list):
            raise ValueError('Invalid dashboard policy')
        if len(policy['routes']) > 50:
            raise ValueError('Too many route rules')
        for rule in policy['routes']:
            if (not isinstance(rule, dict) or rule.get('action') not in ('default', 'block', 'verified')
                    or not isinstance(rule.get('pattern'), str)
                    or not re.fullmatch(r'/[a-zA-Z0-9_\-/.]*\*?', rule['pattern'])):
                raise ValueError('Invalid route rule')
        from urllib.parse import urlsplit
        origin = urlsplit(row['origin_url'])
        if (origin.scheme not in ('http', 'https') or not origin.hostname or origin.username
                or origin.password or origin.query or origin.fragment or origin.path not in ('', '/')):
            raise ValueError('Invalid dashboard origin')
        return replace(settings, origin_url=row['origin_url']), policy

    def record(self, **event):
        timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        try:
            with self.connect() as connection:
                connection.execute(
                    'INSERT OR IGNORE INTO events(request_id,site_id,timestamp,method,path,decision,reason_codes,signals) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (event['request_id'], event['site_id'], timestamp, event['method'], event['path'],
                     event['decision'], json.dumps(event['reasons']), json.dumps(event.get('signals') or {})))
                connection.execute('UPDATE sites SET last_seen = ? WHERE id = ?', (timestamp, event['site_id']))
        except (sqlite3.Error, OSError):
            # Observability must not bypass enforcement or interrupt protected requests.
            logger.exception('Could not persist dashboard event')


def evaluate_dashboard(signals, policy, path):
    decision, reasons = evaluate_signals(signals)
    if signals.session.get('invalid_token'):
        return decision, reasons
    for rule in policy['routes']:
        pattern = rule['pattern']
        matches = path.startswith(pattern[:-1]) if pattern.endswith('*') else path == pattern
        if not matches:
            continue
        if rule['action'] == 'block':
            return Decision.BLOCK, reasons + ['route_policy_block']
        if rule['action'] == 'verified' and not signals.session.get('valid'):
            return Decision.BLOCK, reasons + ['route_requires_verified_session']
        break
    if policy['strictness'] == 'strict' and 'multiple_signal_groups' in reasons:
        return Decision.BLOCK, reasons + ['strict_policy']
    return decision, reasons
