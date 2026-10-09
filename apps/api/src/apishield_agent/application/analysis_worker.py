"""Durable analysis worker, runnable independently of the API process."""
from __future__ import annotations
import argparse
import os
import signal
import threading
from pathlib import Path

from apishield_agent.domain.analysis import deterministic_openapi_diff_bytes
from apishield_agent.domain.contract_input import read_contract
from apishield_agent.infrastructure.store import Store
from apishield_agent.infrastructure.github_sources import GitHubSources


class AnalysisWorker:
    def __init__(self, store, source_reader=None):
        self.store = store
        self.source_reader = source_reader

    def run_once(self):
        row = self.store.claim_pending()
        if not row:
            return False
        try:
            repo = self.store.get_repository(row['tenant_id'], row['repository_id'])
            if repo is None:
                raise ValueError('REPOSITORY_NOT_FOUND')
            if repo['permission_state'] not in {'READ', 'WRITE'}:
                raise PermissionError('REPOSITORY_ACCESS_REVOKED')
            if self.source_reader is not None:
                before, after = self.source_reader.snapshot(row, repo)
            else:
                if os.getenv('APP_ENV', 'development') not in {'development','test'}:
                    raise ValueError('GITHUB_SOURCE_PROVIDER_REQUIRED')
                before = read_contract(repo['before_contract'])
                after = read_contract(repo['after_contract'])
            findings = deterministic_openapi_diff_bytes(before, after)
            current = self.store.get_repository(row['tenant_id'], row['repository_id'])
            if current is None or current['permission_state'] not in {'READ', 'WRITE'}:
                raise PermissionError('REPOSITORY_ACCESS_REVOKED')
            self.store.finish(row['tenant_id'], row['id'], findings, row['lease_token'], source_bytes=(before, after))
        except Exception as error:
            # Persist a bounded, non-sensitive error class, not paths/content.
            self.store.fail(row['tenant_id'], row['id'], type(error).__name__.upper(), row['lease_token'])
        return True

    def serve(self, stop):
        while not stop.is_set():
            if not self.run_once():
                stop.wait(.05)


def main():
    parser = argparse.ArgumentParser(description='APIShield durable analysis worker')
    parser.add_argument('--once', action='store_true', help='Process at most one job and exit')
    args = parser.parse_args()
    if os.getenv('APISHIELD_DATABASE_URL'):
        from apishield_agent.infrastructure.postgres_store import PostgresStore
        store = PostgresStore(os.environ['APISHIELD_DATABASE_URL'])
    else:
        if os.getenv('APP_ENV', 'development') not in {'development', 'test'}:
            parser.error('SQLite is restricted to development/test')
        path = os.getenv('APISHIELD_DB_PATH')
        if not path:
            parser.error('APISHIELD_DB_PATH or APISHIELD_DATABASE_URL must be set')
        store = Store(path)
    worker = AnalysisWorker(store, GitHubSources.from_environment())
    if args.once:
        worker.run_once()
        return
    stop = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stop.set())
    worker.serve(stop)


if __name__ == '__main__':
    main()
