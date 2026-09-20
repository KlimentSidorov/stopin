"""Explicit SQLite provisioning and maintenance; never invoked by public requests."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3


def initialize(path, site_id, domain, origin_url):
    from gateway.config import Settings
    from gateway.dashboard import DashboardStore
    settings = Settings(site_id=site_id)
    settings.validate()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=10) as connection:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)')
        connection.execute('''CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY, domain TEXT NOT NULL UNIQUE, origin_url TEXT NOT NULL,
            policy TEXT NOT NULL DEFAULT '{"strictness":"balanced","routes":[]}', last_seen TEXT)''')
        connection.execute('''CREATE TABLE IF NOT EXISTS events (
            request_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, timestamp TEXT NOT NULL,
            method TEXT NOT NULL, path TEXT NOT NULL, decision TEXT NOT NULL,
            reason_codes TEXT NOT NULL, signals TEXT NOT NULL)''')
        connection.execute('CREATE INDEX IF NOT EXISTS events_site_time ON events(site_id, timestamp)')
        connection.execute('INSERT OR IGNORE INTO schema_migrations VALUES (1)')
        connection.execute('INSERT OR IGNORE INTO sites(id, domain, origin_url) VALUES (?,?,?)',
                           (site_id, domain, origin_url))
    # Reuse exactly the validation used during gateway startup.
    DashboardStore(path).configuration(settings)


def prune(path, site_id, retention_days=30):
    if retention_days < 1:
        raise ValueError('Retention must be at least one day')
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    from gateway.dashboard import DashboardStore
    with DashboardStore(path).connect() as connection:
        return connection.execute('DELETE FROM events WHERE site_id = ? AND timestamp < ?',
                                  (site_id, cutoff)).rowcount


def backup(path, destination):
    if Path(destination).exists():
        raise ValueError('Backup destination already exists')
    if Path(path).resolve() == Path(destination).resolve():
        raise ValueError('Backup must use a different path')
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True) as source:
        with sqlite3.connect(destination) as target:
            source.backup(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'prune', 'backup'))
    parser.add_argument('--db', required=True)
    parser.add_argument('--site', default='local')
    parser.add_argument('--domain')
    parser.add_argument('--origin')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--destination')
    args = parser.parse_args()
    if args.command == 'init':
        if not args.domain or not args.origin:
            parser.error('init requires --domain and --origin')
        initialize(args.db, args.site, args.domain, args.origin)
    elif args.command == 'prune':
        print(prune(args.db, args.site, args.days))
    else:
        if not args.destination:
            parser.error('backup requires --destination')
        backup(args.db, args.destination)


if __name__ == '__main__':
    main()
