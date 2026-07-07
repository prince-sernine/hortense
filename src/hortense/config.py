from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent.parent
DEFAULT_JSONL = Path.cwd() / ".hortense" / "events.jsonl"


def _default_signatures_path() -> Path:
    candidates = [
        PROJECT_ROOT / "configs" / "signatures.yml",
        PACKAGE_ROOT.parent / "configs" / "signatures.yml",
        Path.cwd() / "configs" / "signatures.yml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


DEFAULT_SIGNATURES = _default_signatures_path()


@dataclass(frozen=True)
class Signatures:
    allowlist_processes: list[str]
    allowlist_path_substrings: list[str]
    process_names: list[str]
    path_substrings: list[str]
    process_tree_roots: list[str]
    network_domains: list[str]
    interview_processes: list[str]
    trust_publishers: list[str]
    companion_processes: list[str]
    trust_path_prefixes: list[str]
    suspicious_path_prefixes: list[str]

    @classmethod
    def load(cls, path: Path | None = None) -> Signatures:
        source = path or DEFAULT_SIGNATURES
        try:
            with source.open("r", encoding="utf-8") as handle:
                data: dict[str, Any] = yaml.safe_load(handle) or {}
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"signatures.yml not found at {source}. "
                "Run from the repository root or pass --signatures."
            ) from exc

        return cls(
            allowlist_processes=list(data.get("allowlist_processes") or []),
            allowlist_path_substrings=list(data.get("allowlist_path_substrings") or []),
            process_names=list(data.get("process_names") or []),
            path_substrings=list(data.get("path_substrings") or []),
            process_tree_roots=list(data.get("process_tree_roots") or []),
            network_domains=list(data.get("network_domains") or []),
            interview_processes=list(data.get("interview_processes") or []),
            trust_publishers=list(data.get("trust_publishers") or []),
            companion_processes=list(data.get("companion_processes") or []),
            trust_path_prefixes=list(data.get("trust_path_prefixes") or []),
            suspicious_path_prefixes=list(data.get("suspicious_path_prefixes") or []),
        )


@dataclass(frozen=True)
class ScanConfig:
    signatures_path: Path | None = None
    poll_interval_sec: float = 2.0
    jsonl_path: Path | None = None
    watch_mode: bool = False
    quiet_watch: bool = False
    use_color: bool = True
    sync_catalog: bool = False
    debug: bool = False
    watch_dashboard: bool | None = None

    def resolve_signatures(self) -> Signatures:
        return Signatures.load(self.signatures_path)

    def resolve_jsonl_path(self) -> Path:
        if self.jsonl_path:
            return self.jsonl_path
        return DEFAULT_JSONL
