from __future__ import annotations

import sys
from dataclasses import replace
from typing import Iterable, TextIO

import click

from hortense.entity import format_process_identity, render_detail_line
from hortense.entity_lifecycle import format_signal_label
from hortense.models import DetectionEvent


class HumanReporter:
    SEVERITY_COLORS = {
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "cleared": "green",
    }

    def __init__(self, stream: TextIO | None = None, use_color: bool = True) -> None:
        self.stream = stream or sys.stdout
        tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.use_color = use_color and tty

    def emit(self, event: DetectionEvent) -> None:
        badge = f"[{event.severity.upper()}]"
        if event.severity == "cleared":
            badge = "[CLEARED]"
        if self.use_color:
            color = self.SEVERITY_COLORS.get(event.severity, "white")
            badge = click.style(badge, fg=color, bold=True)
        click.echo(f"{badge} {event.title}", file=self.stream)
        click.echo(f"  {render_detail_line(event)}", file=self.stream)
        identity = format_process_identity(event)
        if identity:
            click.echo(f"  {identity}", file=self.stream)
        if event.window_title:
            click.echo(f"  window: {event.window_title}", file=self.stream)
        still_active = event.metadata.get("still_active")
        if isinstance(still_active, list) and still_active:
            labels = ", ".join(format_signal_label(str(item)) for item in still_active)
            click.echo(f"  still active: {labels}", file=self.stream)
        click.echo("", file=self.stream)

    def emit_many(self, events: Iterable[DetectionEvent]) -> None:
        for event in events:
            self.emit(event)
