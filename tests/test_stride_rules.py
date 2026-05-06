"""Tests for the deterministic STRIDE rule catalogue."""
from __future__ import annotations

import pytest

from generator.parser import Component, ComponentType, Sensitivity
from generator.stride_rules import (
    _SEVERITY_ORDER,
    _shift_severity,
    _sensitivity_delta,
    catalogue_size,
    threats_for,
)
from generator.validator import Severity, StrideCategory


_ALL_TYPES = list(ComponentType)
_ALL_CATEGORIES = list(StrideCategory)


@pytest.mark.parametrize("ctype", _ALL_TYPES)
def test_every_component_type_has_all_six_categories(ctype):
    """Each ComponentType emits at least one threat per STRIDE letter."""
    c = Component(name="x", type=ctype)
    threats = threats_for(c)
    cats = {t.stride_category for t in threats}
    assert cats == set(_ALL_CATEGORIES), (
        f"{ctype.value} missing categories: "
        f"{set(_ALL_CATEGORIES) - cats}")


def test_threat_id_format_is_namespaced():
    c = Component(name="x", type=ComponentType.API)
    for t in threats_for(c):
        # Format: <component_type>.<S|T|R|I|D|E>.<slug>
        parts = t.threat_id.split(".")
        assert parts[0] == "api"
        assert parts[1] in {"S", "T", "R", "I", "D", "E"}
        assert len(parts[2]) > 0


def test_sensitivity_restricted_bumps_severity_up_one():
    c_norm = Component(name="x", type=ComponentType.API,
                        sensitivity=Sensitivity.INTERNAL)
    c_rest = Component(name="x", type=ComponentType.API,
                        sensitivity=Sensitivity.RESTRICTED)
    norms = {t.threat_id: t.severity for t in threats_for(c_norm)}
    rests = {t.threat_id: t.severity for t in threats_for(c_rest)}
    for tid, base in norms.items():
        idx = _SEVERITY_ORDER.index(base)
        # Either bumped one band up, or already at CRITICAL ceiling.
        if idx == len(_SEVERITY_ORDER) - 1:
            assert rests[tid] == base
        else:
            assert (_SEVERITY_ORDER.index(rests[tid])
                     == idx + 1)


def test_sensitivity_public_drops_severity_one():
    c_norm = Component(name="x", type=ComponentType.API,
                        sensitivity=Sensitivity.INTERNAL)
    c_pub = Component(name="x", type=ComponentType.API,
                        sensitivity=Sensitivity.PUBLIC)
    norms = {t.threat_id: t.severity for t in threats_for(c_norm)}
    pubs = {t.threat_id: t.severity for t in threats_for(c_pub)}
    for tid, base in norms.items():
        idx = _SEVERITY_ORDER.index(base)
        if idx == 0:
            assert pubs[tid] == base
        else:
            assert (_SEVERITY_ORDER.index(pubs[tid])
                     == idx - 1)


def test_shift_severity_is_clamped():
    assert _shift_severity(Severity.CRITICAL, +5) == Severity.CRITICAL
    assert _shift_severity(Severity.INFO,     -5) == Severity.INFO
    assert _shift_severity(Severity.MEDIUM,   +1) == Severity.HIGH
    assert _shift_severity(Severity.MEDIUM,   -1) == Severity.LOW


def test_sensitivity_delta_table():
    assert _sensitivity_delta(Sensitivity.RESTRICTED) == +1
    assert _sensitivity_delta(Sensitivity.CONFIDENTIAL) == 0
    assert _sensitivity_delta(Sensitivity.INTERNAL) == 0
    assert _sensitivity_delta(Sensitivity.PUBLIC) == -1


def test_catalogue_size_is_at_least_54():
    """9 component types × 6 STRIDE categories × ≥1 rule each."""
    assert catalogue_size() >= 9 * 6


def test_threats_carry_recommendation_and_references():
    c = Component(name="x", type=ComponentType.WEB_FRONTEND)
    for t in threats_for(c):
        assert t.recommendation
        assert any("Shostack" in r for r in t.references)


def test_threats_for_returns_six_for_simple_type():
    """API has exactly one rule per STRIDE category in the seed catalogue."""
    c = Component(name="x", type=ComponentType.API)
    assert len(threats_for(c)) == 6
