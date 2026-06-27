from __future__ import annotations

import sys
from pathlib import Path

import click

from hortense.config import ScanConfig
from hortense.daemon import ScanDaemon
from hortense.reporters import JsonReporter
from hortense.scanner import has_high_severity, require_windows, run_scan

BANNER = """╻ ╻┏━┓┏━┓╺┳╸┏━╸┏┓╻┏━┓┏━╸
┣━┫┃ ┃┣┳┛ ┃ ┣╸ ┃┗┫┗━┓┣╸ 
╹ ╹┗━┛╹┗╸ ╹ ┗━╸╹ ╹┗━┛┗━╸"""


def emit_banner() -> None:
    click.echo(BANNER)
    click.echo("")


@click.group()
@click.version_option(package_name="hortense")
def main() -> None:
    """Windows interview-integrity scanner (CLI)."""
    require_windows()


@main.command("scan")
@click.option(
    "--signatures",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to signatures.yml",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON array to stdout.")
def scan_cmd(signatures: Path | None, as_json: bool) -> None:
    """Run a one-shot integrity scan."""
    config = ScanConfig(signatures_path=signatures)
    events = run_scan(config)

    if as_json:
        JsonReporter().emit_many(events)
        return

    emit_banner()

    if not events:
        click.echo("No findings.")
        return

    for event in events:
        click.echo(f"[{event.severity.upper()}] {event.title}")
        click.echo(f"  {event.detail}")
        if event.process_name:
            click.echo(f"  process: {event.process_name} (pid={event.pid})")
        if event.window_title:
            click.echo(f"  window: {event.window_title}")
        click.echo("")


@main.command("check")
@click.option(
    "--signatures",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to signatures.yml",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON array to stdout.")
def check_cmd(signatures: Path | None, as_json: bool) -> None:
    """Exit 1 when any high-severity finding is present."""
    config = ScanConfig(signatures_path=signatures)
    events = run_scan(config)

    if as_json:
        JsonReporter().emit_many(events)

    sys.exit(1 if has_high_severity(events) else 0)


@main.command("watch")
@click.option(
    "--signatures",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to signatures.yml",
)
@click.option(
    "--interval",
    default=2.0,
    show_default=True,
    help="Poll interval in seconds.",
)
@click.option(
    "--jsonl",
    type=click.Path(path_type=Path),
    help="Append findings to this JSONL file.",
)
def watch_cmd(signatures: Path | None, interval: float, jsonl: Path | None) -> None:
    """Poll continuously and append findings to JSONL."""
    config = ScanConfig(
        signatures_path=signatures,
        poll_interval_sec=interval,
        jsonl_path=jsonl,
    )
    emit_banner()
    click.echo(f"Watching... logging to {config.resolve_jsonl_path()}")
    ScanDaemon(config).run()


if __name__ == "__main__":
    main()
