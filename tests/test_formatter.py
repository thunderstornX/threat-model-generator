"""Tests for the Markdown / Threat Dragon JSON formatters."""
from __future__ import annotations

import json

import pytest

from generator.formatter import (
    _stable_uuid,
    render_markdown,
    render_threat_dragon,
    write_outputs,
)
from generator.modeller import model_system
from generator.parser import (
    Component,
    ComponentType,
    Sensitivity,
    SystemDescription,
)
from generator.validator import StrideCategory, ThreatModel


def _system() -> SystemDescription:
    return SystemDescription(
        name="MarkdownTest",
        components=[
            Component(name="web", type=ComponentType.WEB_FRONTEND,
                       sensitivity=Sensitivity.RESTRICTED),
            Component(name="db", type=ComponentType.DATABASE,
                       sensitivity=Sensitivity.RESTRICTED),
        ],
    )


def test_render_markdown_contains_header_and_components():
    sys_ = _system()
    model = model_system(sys_)
    md = render_markdown(model)
    assert "# Threat Model: MarkdownTest" in md
    assert "Component: `web`" in md
    assert "Component: `db`" in md
    assert "Spoofing" in md and "Tampering" in md
    assert "## Severity rollup" in md


def test_render_markdown_severity_rollup_matches_count():
    sys_ = _system()
    model = model_system(sys_)
    md = render_markdown(model)
    # Each severity row appears in the rollup table.
    for sev in ("critical", "high", "medium", "low", "info"):
        assert f"| {sev} |" in md


def test_render_threat_dragon_v2_shape():
    sys_ = _system()
    model = model_system(sys_)
    td = render_threat_dragon(sys_, model)
    assert td["version"] == "2.4"
    assert td["summary"]["title"].startswith("Threat Model:")
    diagrams = td["detail"]["diagrams"]
    assert len(diagrams) == 1
    cells = diagrams[0]["diagramJson"]["cells"]
    assert len(cells) == 2
    assert cells[0]["type"] in {"tm.Process", "tm.Store", "tm.Actor"}
    assert "id" in cells[0]
    assert "size" in cells[0] and "position" in cells[0]
    threats0 = cells[0]["data"]["threats"]
    assert len(threats0) >= 6  # one per STRIDE letter from the catalogue
    for tt in threats0:
        assert tt["type"] in {"S", "T", "R", "I", "D", "E"}
        assert tt["modelType"] == "STRIDE"


def test_threat_dragon_json_round_trip_is_serialisable(tmp_path):
    sys_ = _system()
    model = model_system(sys_)
    td = render_threat_dragon(sys_, model)
    s = json.dumps(td)
    back = json.loads(s)
    assert back == td


def test_stable_uuid_is_deterministic():
    a = _stable_uuid("seed-1")
    b = _stable_uuid("seed-1")
    c = _stable_uuid("seed-2")
    assert a == b
    assert a != c
    # Shape: 8-4-4-4-12 hex
    assert len(a) == 36 and a.count("-") == 4


def test_write_outputs_both(tmp_path):
    sys_ = _system()
    model = model_system(sys_)
    written = write_outputs(sys_, model,
                              output_path=tmp_path / "model", fmt="both")
    assert "markdown" in written and "threatdragon" in written
    assert written["markdown"].suffix == ".md"
    assert written["threatdragon"].suffix == ".json"
    assert written["markdown"].exists()


def test_write_outputs_markdown_only(tmp_path):
    sys_ = _system()
    model = model_system(sys_)
    written = write_outputs(sys_, model,
                              output_path=tmp_path / "model.md",
                              fmt="markdown")
    assert "markdown" in written
    assert "threatdragon" not in written


def test_write_outputs_threatdragon_only(tmp_path):
    sys_ = _system()
    model = model_system(sys_)
    written = write_outputs(sys_, model,
                              output_path=tmp_path / "model.json",
                              fmt="threatdragon")
    assert "threatdragon" in written
    assert "markdown" not in written
