"""Tests for the eval harness (helpers + end-to-end on real benchmarks)."""
from __future__ import annotations

from pathlib import Path

from eval.run_eval import (
    _aggregate,
    _benchmark,
    _expected_pairs,
    _observed_pairs,
    _universe,
)
from generator.modeller import model_system
from generator.parser import load_system


def test_universe_size_is_components_times_six(benchmarks_dir):
    sys_ = load_system(benchmarks_dir / "web_app.yaml")
    assert len(_universe(sys_)) == len(sys_.components) * 6


def test_observed_covers_universe_for_well_supported_types(benchmarks_dir):
    """Every component in web_app.yaml has a catalogue entry, so the
    observed set MUST equal the universe."""
    sys_ = load_system(benchmarks_dir / "web_app.yaml")
    model = model_system(sys_)
    assert _observed_pairs(model) == _universe(sys_)


def test_expected_pairs_load_from_sidecar(benchmarks_dir):
    pairs = _expected_pairs(benchmarks_dir / "web_app.expected.json")
    assert ("storefront", "S") in pairs
    assert len(pairs) > 0


def test_benchmark_returns_perfect_recall(benchmarks_dir):
    """Catalogue is exhaustive -> expected ⊆ observed -> recall == 1.0."""
    row = _benchmark(benchmarks_dir / "web_app.yaml")
    assert row["recall"] == 1.0
    assert row["fn"] == 0


def test_benchmark_precision_is_finite_and_le_one(benchmarks_dir):
    row = _benchmark(benchmarks_dir / "web_app.yaml")
    assert 0.0 < row["precision"] <= 1.0


def test_aggregate_micro_averages():
    rows = [
        {"tp": 5, "fp": 1, "fn": 0, "tn": 0},
        {"tp": 4, "fp": 0, "fn": 1, "tn": 0},
    ]
    a = _aggregate(rows)
    assert a["tp"] == 9
    assert a["fp"] == 1
    assert a["fn"] == 1
    assert a["precision"] == round(9 / 10, 4)
    assert a["recall"] == round(9 / 10, 4)


def test_all_five_benchmarks_load(benchmarks_dir):
    """Smoke: every benchmark file pair loads without error."""
    yaml_files = sorted(benchmarks_dir.glob("*.yaml"))
    assert len(yaml_files) == 5
    for y in yaml_files:
        row = _benchmark(y)
        assert row["recall"] == 1.0
        assert 0.0 < row["precision"] <= 1.0
