from __future__ import annotations

from pathlib import Path

import yaml

from hortense.config import DEFAULT_JSONL, ScanConfig, Signatures


def test_signatures_loads_allowlist_and_cluely_tree(tmp_path: Path) -> None:
    source = tmp_path / "signatures.yml"
    source.write_text(
        yaml.safe_dump(
            {
                "allowlist_processes": ["zoom.exe"],
                "allowlist_path_substrings": ["\\program files\\zoom\\"],
                "process_tree_roots": ["cluely-v2"],
                "process_names": ["cluely"],
            }
        ),
        encoding="utf-8",
    )

    sig = Signatures.load(source)
    assert "zoom.exe" in sig.allowlist_processes
    assert any("zoom" in entry for entry in sig.allowlist_path_substrings)
    assert "cluely-v2" in sig.process_tree_roots


def test_signatures_load_linkjobai_tree(tmp_path: Path) -> None:
    source = tmp_path / "signatures.yml"
    source.write_text(
        yaml.safe_dump(
            {
                "process_names": ["lynccontainer", "linkjobai"],
                "path_substrings": ["linkjobai", "aihirely"],
                "process_tree_roots": ["com.aihirely.linkjobai"],
            }
        ),
        encoding="utf-8",
    )

    sig = Signatures.load(source)
    assert "lynccontainer" in sig.process_names
    assert "aihirely" in sig.path_substrings
    assert "com.aihirely.linkjobai" in sig.process_tree_roots


def test_default_signatures_include_linkjobai_coverage() -> None:
    sig = Signatures.load(Path("configs/signatures.yml"))
    assert "lynccontainer" in sig.process_names
    assert "linkjobai" in sig.path_substrings
    assert "com.aihirely.linkjobai" in sig.process_tree_roots


def test_default_jsonl_path_is_project_local() -> None:
    assert ScanConfig().resolve_jsonl_path() == DEFAULT_JSONL
    assert DEFAULT_JSONL.name == "events.jsonl"
    assert DEFAULT_JSONL.parent.name == ".hortense"
    assert DEFAULT_JSONL.parent.parent == Path.cwd()


def test_explicit_jsonl_path_overrides_default(tmp_path: Path) -> None:
    path = tmp_path / "custom.jsonl"
    assert ScanConfig(jsonl_path=path).resolve_jsonl_path() == path
