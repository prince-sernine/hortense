from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hortense.catalog import TrustedCatalog, catalog_update
from hortense.config import PROJECT_ROOT


def test_trusted_catalog_merge_includes_seed_and_signatures(tmp_path: Path) -> None:
    catalog = TrustedCatalog.load_merged(
        signatures_trust_publishers=["Example Corp"],
        signatures_companion=["Helper.exe"],
        signatures_trust_paths=[r"\program files\example\\"],
    )
    assert "Example Corp" in catalog.trust_publishers
    assert "Helper.exe" in catalog.companion_processes
    assert any("bitdefender" in p.casefold() for p in catalog.tier1_publishers)


def test_catalog_update_writes_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = catalog_update()
    assert path.exists()
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload.get("updated_at")


def test_seed_file_exists() -> None:
    assert (PROJECT_ROOT / "configs" / "trusted_catalog.seed.yml").exists()
