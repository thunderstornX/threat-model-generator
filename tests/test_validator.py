"""Tests for the ThreatModel Pydantic schema."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from generator.validator import (
    Severity,
    StrideCategory,
    Threat,
    ThreatModel,
)


def _t() -> Threat:
    return Threat(
        threat_id="x.S.foo",
        component="comp",
        component_type="api",
        stride_category=StrideCategory.SPOOFING,
        title="T",
        description="D",
        recommendation="R",
    )


def test_threat_round_trip_through_json():
    t = _t()
    s = t.model_dump_json()
    back = Threat.model_validate_json(s)
    assert back == t


def test_threat_rejects_blank_title():
    with pytest.raises(ValidationError):
        Threat(
            threat_id="x", component="c", component_type="api",
            stride_category=StrideCategory.SPOOFING,
            title="", description="d", recommendation="r",
        )


def test_threat_default_severity_is_medium():
    assert _t().severity == Severity.MEDIUM


def test_threat_model_round_trip():
    m = ThreatModel(system_name="S", threats=[_t(), _t()])
    s = m.model_dump_json()
    back = ThreatModel.model_validate_json(s)
    assert back.system_name == m.system_name
    assert back.threat_count == 2


def test_threat_model_by_component_groups():
    m = ThreatModel(system_name="S", threats=[
        _t(),
        Threat(
            threat_id="y.T.bar", component="other", component_type="api",
            stride_category=StrideCategory.TAMPERING,
            title="A", description="B", recommendation="C",
        ),
    ])
    grouped = m.by_component()
    assert set(grouped.keys()) == {"comp", "other"}
    assert len(grouped["comp"]) == 1


def test_threat_model_by_category_groups():
    m = ThreatModel(system_name="S", threats=[_t(),
        Threat(
            threat_id="y.T.bar", component="comp2", component_type="api",
            stride_category=StrideCategory.TAMPERING,
            title="A", description="B", recommendation="C",
        ),
    ])
    grouped = m.by_category()
    assert "spoofing" in grouped
    assert "tampering" in grouped


def test_threat_model_rejects_extra_fields():
    with pytest.raises(ValidationError):
        ThreatModel.model_validate({
            "system_name": "S",
            "unexpected": "x",
        })
