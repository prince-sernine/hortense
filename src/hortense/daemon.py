from __future__ import annotations

import signal
import time

from hortense.config import ScanConfig
from hortense.human_reporter import HumanReporter
from hortense.models import DetectionEvent
from hortense.relay_lifecycle import RelayLifecycleTracker
from hortense.reporters import JsonlReporter
from hortense.scanner import run_scan


class ScanDaemon:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.reporter = JsonlReporter(self.config.resolve_jsonl_path())
        self.human = HumanReporter(use_color=self.config.use_color)
        self.lifecycle = RelayLifecycleTracker()
        self._seen_ids: set[str] = set()
        self._running = True

    def stop(self, *_args) -> None:
        self._running = False

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        watch_config = ScanConfig(
            signatures_path=self.config.signatures_path,
            poll_interval_sec=self.config.poll_interval_sec,
            jsonl_path=self.config.jsonl_path,
            watch_mode=True,
            quiet_watch=self.config.quiet_watch,
            use_color=self.config.use_color,
        )

        while self._running:
            events = run_scan(watch_config, lifecycle_tracker=self.lifecycle)
            fresh = self._fresh_events(events)
            if fresh:
                self.reporter.emit_many(fresh)
                if not self.config.quiet_watch:
                    self.human.emit_many(fresh)
            time.sleep(self.config.poll_interval_sec)

    def _fresh_events(self, events: list[DetectionEvent]) -> list[DetectionEvent]:
        fresh: list[DetectionEvent] = []
        for event in events:
            if event.id in self._seen_ids:
                continue
            self._seen_ids.add(event.id)
            fresh.append(event)
        return fresh
