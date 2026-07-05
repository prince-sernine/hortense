from __future__ import annotations

import sys
from pathlib import Path

import click

from hortense.config import ScanConfig
from hortense.daemon import ScanDaemon
from hortense.human_reporter import HumanReporter
from hortense.reporters import JsonReporter
from hortense.scanner import has_high_severity, require_windows, run_scan

BANNER = """╻ ╻┏━┓┏━┓╺┳╸┏━╸┏┓╻┏━┓┏━╸
┣━┫┃ ┃┣┳┛ ┃ ┣╸ ┃┗┫┗━┓┣╸ 
╹ ╹┗━┛╹┗╸ ╹ ┗━╸╹ ╹┗━┛┗━╸"""
ASCII_BANNER = "HORTENSE"


def emit_banner() -> None:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        BANNER.encode(encoding)
        banner = BANNER
    except UnicodeEncodeError:
        banner = ASCII_BANNER

    click.echo(banner)
    click.echo("")


def _resolve_color(no_color: bool) -> bool:
    return not no_color


@click.group()
@click.option("--no-color", is_flag=True, help="Disable ANSI severity colors.")
@click.pass_context
@click.version_option(package_name="hortense")
def main(ctx: click.Context, no_color: bool) -> None:
    """Windows interview-integrity scanner (CLI)."""
    require_windows()
    ctx.ensure_object(dict)
    ctx.obj["use_color"] = _resolve_color(no_color)


@main.command("scan")
@click.option(
    "--signatures",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to signatures.yml",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON array to stdout.")
@click.pass_context
def scan_cmd(ctx: click.Context, signatures: Path | None, as_json: bool) -> None:
    """Run a one-shot integrity scan."""
    config = ScanConfig(
        signatures_path=signatures,
        use_color=ctx.obj.get("use_color", True),
    )
    events = run_scan(config)

    if as_json:
        JsonReporter().emit_many(events)
        return

    emit_banner()

    if not events:
        click.echo("No findings.")
        return

    HumanReporter(use_color=config.use_color).emit_many(events)


@main.command("check")
@click.option(
    "--signatures",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to signatures.yml",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON array to stdout.")
@click.pass_context
def check_cmd(ctx: click.Context, signatures: Path | None, as_json: bool) -> None:
    """Exit 1 when any high-severity finding is present."""
    config = ScanConfig(
        signatures_path=signatures,
        use_color=ctx.obj.get("use_color", True),
    )
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
@click.option(
    "--quiet",
    is_flag=True,
    help="JSONL only; do not print live findings to the terminal.",
)
@click.pass_context
def watch_cmd(
    ctx: click.Context,
    signatures: Path | None,
    interval: float,
    jsonl: Path | None,
    quiet: bool,
) -> None:
    """Poll continuously; log findings to JSONL and print new hits live."""
    config = ScanConfig(
        signatures_path=signatures,
        poll_interval_sec=interval,
        jsonl_path=jsonl,
        watch_mode=True,
        quiet_watch=quiet,
        use_color=ctx.obj.get("use_color", True),
    )
    emit_banner()
    click.echo(f"Watching... logging to {config.resolve_jsonl_path()}")
    if quiet:
        click.echo("Live terminal output disabled (--quiet).")
    ScanDaemon(config).run()


if __name__ == "__main__":
    main()
