from __future__ import annotations

import signal
import sys
import time

from hortense.config import ScanConfig
from hortense.entity_lifecycle import EntityLifecycleTracker
from hortense.human_reporter import HumanReporter
from hortense.models import DetectionEvent
from hortense.reporters import JsonlReporter
from hortense.scanner import run_scan
from hortense.watch_state import (
    WatchState,
    display_key,
    meeting_apps_header,
    ordered_for_watch,
)
from hortense.watch_tui import WatchTui, WatchTuiUnavailable

TUI_RECENT_EVENT_LIMIT = 100


class ScanDaemon:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.reporter = JsonlReporter(self.config.resolve_jsonl_path())
        self.human = HumanReporter(use_color=self.config.use_color)
        self.lifecycle = EntityLifecycleTracker()
        self.state = WatchState()
        self._seen_ids: set[str] = set()
        self._seen_display_keys: set[str] = set()
        self._last_meeting_apps: tuple[str, ...] | None = None
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
            sync_catalog=self.config.sync_catalog,
            debug=self.config.debug,
            watch_dashboard=self.config.watch_dashboard,
        )

        if self._use_tui():
            try:
                WatchTui(
                    self.state,
                    poll_once=lambda: self._poll_once(watch_config, emit_classic=False),
                    interval_sec=self.config.poll_interval_sec,
                    jsonl_path=str(watch_config.resolve_jsonl_path()),
                ).run()
                return
            except WatchTuiUnavailable as exc:
                print(f"hortense: {exc}; falling back to classic watch output.", file=sys.stderr)

        wants_tui = (
            not self.config.quiet_watch
            and not self.config.debug
            and self.config.watch_dashboard is not False
            and hasattr(sys.stdout, "isatty")
            and sys.stdout.isatty()
        )
        if wants_tui and not WatchTui.available():
            print(
                "hortense: prompt_toolkit unavailable; falling back to classic watch output.",
                file=sys.stderr,
            )
        try:
            while self._running:
                self._poll_once(watch_config, emit_classic=True)
                time.sleep(self.config.poll_interval_sec)
        finally:
            return

    def _poll_once(self, watch_config: ScanConfig, *, emit_classic: bool) -> None:
        events = run_scan(watch_config, lifecycle_tracker=self.lifecycle)
        fresh = self._fresh_events(events)
        display_events = self._fresh_display_events(fresh)
        self._update_state(events, display_events)

        if fresh:
            self.reporter.emit_many(fresh)

        if not emit_classic or self.config.quiet_watch:
            return

        self._emit_meeting_app_change()
        if display_events:
            self.human.emit_many(display_events)

    def _fresh_events(self, events: list[DetectionEvent]) -> list[DetectionEvent]:
        fresh: list[DetectionEvent] = []
        for event in events:
            if event.id in self._seen_ids:
                continue
            self._seen_ids.add(event.id)
            fresh.append(event)
        return fresh

    def _fresh_display_events(self, events: list[DetectionEvent]) -> list[DetectionEvent]:
        fresh: list[DetectionEvent] = []
        for event in ordered_for_watch(events):
            key = display_key(event)
            if key in self._seen_display_keys:
                continue
            self._seen_display_keys.add(key)
            fresh.append(event)
        return fresh

    def _update_state(
        self,
        events: list[DetectionEvent],
        display_events: list[DetectionEvent],
    ) -> None:
        snapshot = self.lifecycle.active_snapshot()
        self.state.active_clusters = snapshot
        self.state.pre_call_clusters = [] if self.lifecycle.meeting_app_count > 0 else snapshot
        self.state.meeting_apps = list(self.lifecycle.meeting_app_names)
        self.state.raw_meeting_apps = list(self.lifecycle.raw_meeting_app_names)
        self.state.events.extend(display_events)
        self.state.events = self.state.events[-TUI_RECENT_EVENT_LIMIT:]
        if display_events:
            self.state.scroll_offset = 0

    def _emit_meeting_app_change(self) -> None:
        current = tuple(self.state.meeting_apps)
        if current == self._last_meeting_apps:
            return
        self._last_meeting_apps = current
        print(f"Meeting apps open: {meeting_apps_header(list(current), limit=99)}")

    def _use_tui(self) -> bool:
        if self.config.quiet_watch:
            return False
        if self.config.debug:
            return False
        enabled = self.config.watch_dashboard
        if enabled is None:
            enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        if not enabled:
            return False
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        return WatchTui.available()
