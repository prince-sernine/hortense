from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from hortense.config import PROJECT_ROOT

SEED_PATH = PROJECT_ROOT / "configs" / "trusted_catalog.seed.yml"
LOCAL_DIR = Path.cwd() / ".hortense"
CACHE_PATH = LOCAL_DIR / "trusted_catalog.yml"
OVERRIDES_PATH = LOCAL_DIR / "catalog_overrides.yml"
STALE_DAYS = 14


@dataclass(frozen=True)
class TrustedCatalog:
    catalog_version: int
    updated_at: str | None
    tier1_publishers: list[str]
    tier2_publishers: list[str]
    trust_publishers: list[str]
    companion_processes: list[str]
    trust_path_prefixes: list[str]
    cloud_sync_path_prefixes: list[str]
    processes: list[dict[str, Any]]

    @classmethod
    def load_merged(
        cls,
        *,
        signatures_trust_publishers: list[str] | None = None,
        signatures_companion: list[str] | None = None,
        signatures_trust_paths: list[str] | None = None,
    ) -> TrustedCatalog:
        layers: list[dict[str, Any]] = []
        for path in (SEED_PATH, CACHE_PATH, OVERRIDES_PATH):
            if path.exists():
                with path.open("r", encoding="utf-8") as handle:
                    layers.append(yaml.safe_load(handle) or {})

        merged: dict[str, Any] = {
            "catalog_version": 1,
            "updated_at": None,
            "tier1_publishers": [],
            "tier2_publishers": [],
            "trust_publishers": [],
            "companion_processes": [],
            "trust_path_prefixes": [],
            "cloud_sync_path_prefixes": [],
            "processes": [],
        }

        list_keys = [
            "tier1_publishers",
            "tier2_publishers",
            "trust_publishers",
            "companion_processes",
            "trust_path_prefixes",
            "cloud_sync_path_prefixes",
        ]
        for layer in layers:
            if "catalog_version" in layer:
                merged["catalog_version"] = layer["catalog_version"]
            if layer.get("updated_at"):
                merged["updated_at"] = layer["updated_at"]
            for key in list_keys:
                merged[key] = _merge_unique(merged[key], layer.get(key) or [])
            merged["processes"] = _merge_processes(
                merged["processes"], layer.get("processes") or []
            )

        if signatures_trust_publishers:
            merged["trust_publishers"] = _merge_unique(
                merged["trust_publishers"], signatures_trust_publishers
            )
        if signatures_companion:
            merged["companion_processes"] = _merge_unique(
                merged["companion_processes"], signatures_companion
            )
        if signatures_trust_paths:
            merged["trust_path_prefixes"] = _merge_unique(
                merged["trust_path_prefixes"], signatures_trust_paths
            )

        all_publishers = _merge_unique(
            merged["trust_publishers"],
            merged["tier1_publishers"],
            merged["tier2_publishers"],
        )

        return cls(
            catalog_version=int(merged["catalog_version"]),
            updated_at=merged.get("updated_at"),
            tier1_publishers=list(merged["tier1_publishers"]),
            tier2_publishers=list(merged["tier2_publishers"]),
            trust_publishers=all_publishers,
            companion_processes=list(merged["companion_processes"]),
            trust_path_prefixes=list(merged["trust_path_prefixes"]),
            cloud_sync_path_prefixes=list(merged["cloud_sync_path_prefixes"]),
            processes=list(merged["processes"]),
        )

    def age_days(self) -> int | None:
        if not self.updated_at:
            return None
        try:
            updated = datetime.fromisoformat(self.updated_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - updated
        return max(delta.days, 0)

    def is_stale(self) -> bool:
        age = self.age_days()
        if age is None:
            return CACHE_PATH.exists() is False
        return age >= STALE_DAYS


def _merge_unique(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        for item in group:
            key = item.strip()
            if not key:
                continue
            fold = key.casefold()
            if fold in seen:
                continue
            seen.add(fold)
            out.append(key)
    return out


def _merge_processes(
    base: list[dict[str, Any]], extra: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for entry in base + extra:
        name = str(entry.get("name", "")).casefold()
        if not name:
            continue
        by_name[name] = entry
    return list(by_name.values())


def catalog_update() -> Path:
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    if not SEED_PATH.exists():
        raise FileNotFoundError(f"Trust seed missing at {SEED_PATH}")
    payload = yaml.safe_load(SEED_PATH.read_text(encoding="utf-8")) or {}
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    with CACHE_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    return CACHE_PATH


def catalog_status_text(catalog: TrustedCatalog) -> str:
    lines = [
        f"catalog_version: {catalog.catalog_version}",
        f"cache_path: {CACHE_PATH}",
        f"cache_exists: {CACHE_PATH.exists()}",
        f"updated_at: {catalog.updated_at or 'unknown'}",
    ]
    age = catalog.age_days()
    if age is not None:
        lines.append(f"age_days: {age}")
    lines.append(f"stale: {catalog.is_stale()}")
    lines.append(f"tier1_publishers: {len(catalog.tier1_publishers)}")
    lines.append(f"tier2_publishers: {len(catalog.tier2_publishers)}")
    lines.append(f"trust_publishers_total: {len(catalog.trust_publishers)}")
    lines.append(f"companion_processes: {len(catalog.companion_processes)}")
    return "\n".join(lines)


def seed_catalog_if_missing() -> None:
    if CACHE_PATH.exists():
        return
    catalog_update()
