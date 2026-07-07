from __future__ import annotations

import shutil
import threading
from collections.abc import Callable

from hortense.watch_dashboard import (
    WatchDashboardFormatter,
    cluster_confidence_line,
    cluster_header_suffix,
    cluster_pid_line,
)
from hortense.watch_state import WatchState

CLUSTER_PANE_HEIGHT = 9
CLUSTER_PANE_CONTENT_LINES = 7


class WatchTuiUnavailable(RuntimeError):
    pass


class WatchTui:
    def __init__(
        self,
        state: WatchState,
        *,
        poll_once: Callable[[], None],
        interval_sec: float,
        jsonl_path: str,
    ) -> None:
        self.state = state
        self.poll_once = poll_once
        self.interval_sec = interval_sec
        self.jsonl_path = jsonl_path
        self.formatter = WatchDashboardFormatter()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._error: Exception | None = None
        self._app = None

    @staticmethod
    def available() -> bool:
        try:
            import prompt_toolkit  # noqa: F401
        except ImportError:
            return False
        return True

    def run(self) -> None:
        try:
            from prompt_toolkit.application import Application
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.layout import Layout
            from prompt_toolkit.layout.controls import FormattedTextControl
            from prompt_toolkit.layout.containers import HSplit, VSplit, Window
            from prompt_toolkit.styles import Style
            from prompt_toolkit.widgets import Frame
        except ImportError as exc:
            raise WatchTuiUnavailable("prompt_toolkit is not installed") from exc

        kb = KeyBindings()

        @kb.add("q")
        @kb.add("c-c")
        def _quit(event) -> None:
            self._stop.set()
            event.app.exit()

        @kb.add("up")
        def _up(event) -> None:
            with self._lock:
                self.state.scroll_offset = min(self.state.scroll_offset + 1, self._max_scroll())
            event.app.invalidate()

        @kb.add("down")
        def _down(event) -> None:
            with self._lock:
                self.state.scroll_offset = max(self.state.scroll_offset - 1, 0)
            event.app.invalidate()

        @kb.add("pageup")
        def _page_up(event) -> None:
            with self._lock:
                self.state.scroll_offset = min(self.state.scroll_offset + 10, self._max_scroll())
            event.app.invalidate()

        @kb.add("pagedown")
        def _page_down(event) -> None:
            with self._lock:
                self.state.scroll_offset = max(self.state.scroll_offset - 10, 0)
            event.app.invalidate()

        @kb.add("home")
        def _home(event) -> None:
            with self._lock:
                self.state.scroll_offset = self._max_scroll()
            event.app.invalidate()

        @kb.add("end")
        def _end(event) -> None:
            with self._lock:
                self.state.scroll_offset = 0
            event.app.invalidate()

        try:
            header = Window(
                content=FormattedTextControl(lambda: self._header_fragments()),
                height=1,
                wrap_lines=False,
                always_hide_cursor=True,
            )
            clusters = Frame(
                Window(
                    content=FormattedTextControl(lambda: self._cluster_fragments()),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                title="Clusters",
            )
            meeting = Frame(
                Window(
                    content=FormattedTextControl(lambda: self._meeting_fragments()),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                title="Meeting apps",
                width=28,
            )
            events = Frame(
                Window(
                    content=FormattedTextControl(lambda: self._event_fragments()),
                    wrap_lines=False,
                    always_hide_cursor=True,
                ),
                title="Events",
            )
            footer = Window(
                content=FormattedTextControl(lambda: self._footer_fragments()),
                height=1,
                wrap_lines=False,
                always_hide_cursor=True,
            )
            app = Application(
                layout=Layout(
                    HSplit(
                        [
                            header,
                            VSplit([clusters, meeting], height=CLUSTER_PANE_HEIGHT),
                            events,
                            footer,
                        ]
                    )
                ),
                key_bindings=kb,
                full_screen=True,
                mouse_support=True,
                refresh_interval=0.5,
                style=Style.from_dict(
                    {
                        "title": "bold bg:#1f2937 #ffffff",
                        "state.active": "bold #ff5c57",
                        "state.precall": "bold #f3f99d",
                        "muted": "#8a8f98",
                        "high": "bold #ff5c57",
                        "medium": "bold #f3f99d",
                        "low": "#57c7ff",
                        "cleared": "bold #5af78e",
                        "label": "bold #9aedfe",
                        "footer": "bg:#1f2937 #c7d0d9",
                    }
                ),
            )
            self._app = app
        except Exception as exc:
            raise WatchTuiUnavailable("prompt_toolkit could not initialize this terminal") from exc

        worker = threading.Thread(target=self._poll_loop, args=(app,), daemon=True)
        worker.start()
        app.run()
        self._stop.set()
        worker.join(timeout=2)
        if self._error is not None:
            raise self._error

    def _poll_loop(self, app) -> None:
        while not self._stop.is_set():
            try:
                with self._lock:
                    self.poll_once()
                    self.state.scroll_offset = min(self.state.scroll_offset, self._max_scroll())
                app.invalidate()
            except Exception as exc:  # pragma: no cover - surfaced after TUI exits
                self._error = exc
                self._stop.set()
                app.exit()
                return
            self._stop.wait(self.interval_sec)

    def _header_fragments(self) -> list[tuple[str, str]]:
        with self._lock:
            mode = "ACTIVE" if self.state.meeting_app_count > 0 else "PRE-CALL"
            mode_style = "class:state.active" if mode == "ACTIVE" else "class:state.precall"
            clusters = len(self._current_clusters())
            signals = sum(item.signal_count for item in self._current_clusters())
            high = sum(item.severity_counts.get("high", 0) for item in self._current_clusters())
            medium = sum(item.severity_counts.get("medium", 0) for item in self._current_clusters())
            meeting_label = self.formatter.header_lines(self.state)[0].split("meeting apps: ", 1)[-1]
            return [
                ("class:title", " HORTENSE WATCH "),
                ("", " "),
                (mode_style, mode),
                ("class:muted", "  "),
                ("class:label", "clusters="),
                ("", str(clusters)),
                ("class:muted", "  "),
                ("class:label", "signals="),
                ("", str(signals)),
                ("class:muted", "  "),
                ("class:high", f"high={high}"),
                ("class:muted", "  "),
                ("class:medium", f"medium={medium}"),
                ("class:muted", "  "),
                ("class:label", "meeting apps: "),
                ("", meeting_label),
            ]

    def _cluster_fragments(self) -> list[tuple[str, str]]:
        with self._lock:
            clusters = self._current_clusters()
            if not clusters:
                return [("class:muted", "No active clusters")]
            fragments: list[tuple[str, str]] = []
            used_lines = 0
            for index, cluster in enumerate(clusters):
                pid_line = cluster_pid_line(cluster)
                confidence_line = cluster_confidence_line(cluster)
                rendered_lines = 2 + (1 if confidence_line else 0) + (1 if pid_line else 0)
                remaining_clusters = len(clusters) - index - 1
                reserve_overflow = 1 if remaining_clusters > 0 else 0
                if (
                    pid_line
                    and confidence_line
                    and used_lines + rendered_lines + reserve_overflow > CLUSTER_PANE_CONTENT_LINES
                ):
                    pid_line = None
                    rendered_lines -= 1
                if used_lines + rendered_lines + reserve_overflow > CLUSTER_PANE_CONTENT_LINES:
                    fragments.append(
                        ("class:muted", f"+{len(clusters) - index} more clusters")
                    )
                    used_lines += 1
                    break
                severity_style = "class:high" if cluster.severity_counts.get("high") else "class:medium"
                fragments.extend(
                    [
                        (severity_style, cluster.display_name),
                        ("class:muted", "  "),
                        ("class:label", f"{cluster.signal_count} signals"),
                        ("class:muted", cluster_header_suffix(cluster)),
                        ("", "\n"),
                        ("class:muted", "  "),
                        ("", "  ".join(cluster.signals)),
                        ("", "\n"),
                    ]
                )
                used_lines += 2
                if confidence_line:
                    fragments.extend(
                        [
                            ("class:muted", "  "),
                            ("class:label", confidence_line),
                            ("", "\n"),
                        ]
                    )
                    used_lines += 1
                if pid_line:
                    fragments.extend(
                        [
                            ("class:muted", "  "),
                            ("", pid_line),
                            ("", "\n"),
                        ]
                    )
                    used_lines += 1
            return fragments

    def _meeting_fragments(self) -> list[tuple[str, str]]:
        with self._lock:
            if not self.state.meeting_apps:
                return [("class:muted", "none")]
            fragments: list[tuple[str, str]] = []
            for name in self.state.meeting_apps[:8]:
                fragments.extend([("class:label", name), ("", "\n")])
            overflow = len(self.state.meeting_apps) - 8
            if overflow > 0:
                fragments.append(("class:muted", f"+{overflow} more"))
            return fragments

    def _event_fragments(self) -> list[tuple[str, str]]:
        with self._lock:
            height = self._event_view_height()
            width = self._event_view_width()
            self.state.scroll_offset = min(self.state.scroll_offset, self._max_scroll(height=height))
            lines = self._visible_event_lines(height=height)
            if not lines:
                return [("class:muted", "No events yet")]
            fragments: list[tuple[str, str]] = []
            for line in lines:
                fragments.extend(self._styled_event_line(self._fit_line(line, width=width)))
                fragments.append(("", "\n"))
            return fragments

    def _footer_fragments(self) -> list[tuple[str, str]]:
        status = "live" if self.state.scroll_offset == 0 else f"review +{self.state.scroll_offset}"
        prefix = f" q quit | Home/End | {status} | recent 100 | full log: "
        width = self._terminal_columns()
        path_budget = max(width - len(prefix), 10)
        path = self._short_path(self.jsonl_path, max_chars=path_budget)
        return [
            ("class:footer", prefix),
            ("class:footer", path),
        ]

    def _current_clusters(self):
        return (
            self.state.active_clusters
            if self.state.meeting_app_count > 0
            else self.state.pre_call_clusters
        )

    def _styled_event_line(self, line: str) -> list[tuple[str, str]]:
        if line.startswith("[HIGH]"):
            return [("class:high", "[HIGH]"), ("", line.removeprefix("[HIGH]"))]
        if line.startswith("[MEDIUM]"):
            return [("class:medium", "[MEDIUM]"), ("", line.removeprefix("[MEDIUM]"))]
        if line.startswith("[LOW]"):
            return [("class:low", "[LOW]"), ("", line.removeprefix("[LOW]"))]
        if line.startswith("[CLEARED]"):
            return [("class:cleared", "[CLEARED]"), ("", line.removeprefix("[CLEARED]"))]
        if line.startswith("  "):
            return [("class:muted", line)]
        return [("", line)]

    def _terminal_rows(self) -> int:
        app = self._app
        if app is not None:
            try:
                return int(app.output.get_size().rows)
            except Exception:
                pass
        return shutil.get_terminal_size(fallback=(100, 30)).lines

    def _terminal_columns(self) -> int:
        app = self._app
        if app is not None:
            try:
                return int(app.output.get_size().columns)
            except Exception:
                pass
        return shutil.get_terminal_size(fallback=(100, 30)).columns

    def _event_view_height(self) -> int:
        # Header + cluster/meeting pane + footer + event frame borders.
        reserved_rows = 1 + CLUSTER_PANE_HEIGHT + 1 + 2
        return max(self._terminal_rows() - reserved_rows, 1)

    def _event_view_width(self) -> int:
        # Event frame borders and one column of breathing room.
        return max(self._terminal_columns() - 4, 20)

    @staticmethod
    def _short_path(path: str, *, max_chars: int = 54) -> str:
        if len(path) <= max_chars:
            return path
        keep = max(max_chars - 3, 10)
        head = max(keep // 3, 4)
        tail = keep - head
        return f"{path[:head]}...{path[-tail:]}"

    @staticmethod
    def _fit_line(line: str, *, width: int) -> str:
        if len(line) <= width:
            return line
        if width <= 3:
            return line[:width]
        return f"{line[: width - 3]}..."

    def _render(self) -> str:
        with self._lock:
            lines = self.formatter.header_lines(self.state)
            lines.append("")
            clusters = self._current_clusters()
            lines.extend(self.formatter.cluster_lines(clusters, limit=5))
            lines.append("")
            lines.extend(self.formatter.meeting_app_lines(self.state, limit=6))
            lines.append("")
            lines.append("Events")
            lines.append("-" * 72)
            event_lines = self._visible_event_lines(height=12)
            lines.extend(event_lines or ["No events yet"])
            lines.append("")
            lines.append(
                f"q quit | arrows/PgUp/PgDn scroll | jsonl: {self._short_path(self.jsonl_path)}"
            )
            return "\n".join(lines)

    def _visible_event_lines(self, *, height: int = 12) -> list[str]:
        all_lines = self.state.event_lines()
        if not all_lines:
            return []
        height = max(height, 1)
        self.state.scroll_offset = min(self.state.scroll_offset, self._max_scroll(height=height))
        end = max(len(all_lines) - self.state.scroll_offset, 0)
        start = max(end - height, 0)
        return all_lines[start:end]

    def _max_scroll(self, *, height: int | None = None) -> int:
        visible_height = height if height is not None else self._event_view_height()
        return max(len(self.state.event_lines()) - max(visible_height, 1), 0)
