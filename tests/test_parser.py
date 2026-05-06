"""Tests for the YAML system-description parser."""
from __future__ import annotations

import pytest

from generator.parser import (
    Component,
    ComponentType,
    Sensitivity,
    SystemDescription,
    load_system,
    parse_system,
)


def test_parse_minimal_system():
    yaml_text = """
name: TinySystem
components:
  - name: web
    type: web_frontend
"""
    sys_ = parse_system(yaml_text)
    assert sys_.name == "TinySystem"
    assert len(sys_.components) == 1
    assert sys_.components[0].type == ComponentType.WEB_FRONTEND
    assert sys_.components[0].sensitivity == Sensitivity.INTERNAL


def test_parse_full_system_round_trip(benchmarks_dir):
    sys_ = load_system(benchmarks_dir / "web_app.yaml")
    assert sys_.name == "ExampleShop"
    assert len(sys_.components) == 4
    types = {c.type for c in sys_.components}
    assert ComponentType.WEB_FRONTEND in types
    assert ComponentType.DATABASE in types


def test_parse_rejects_unknown_component_type():
    yaml_text = """
name: X
components:
  - name: foo
    type: not_a_real_type
"""
    with pytest.raises(ValueError):
        parse_system(yaml_text)


def test_parse_rejects_empty_components():
    yaml_text = """
name: X
components: []
"""
    with pytest.raises(ValueError):
        parse_system(yaml_text)


def test_parse_rejects_duplicate_component_names():
    yaml_text = """
name: X
components:
  - name: foo
    type: web_frontend
  - name: foo
    type: api
"""
    with pytest.raises(ValueError):
        parse_system(yaml_text)


def test_parse_rejects_extra_top_level_field():
    yaml_text = """
name: X
some_unexpected_field: 1
components:
  - name: foo
    type: api
"""
    with pytest.raises(ValueError):
        parse_system(yaml_text)


def test_parse_rejects_non_mapping_top_level():
    with pytest.raises(ValueError):
        parse_system("just a string")


def test_parse_rejects_blank_component_name():
    yaml_text = """
name: X
components:
  - name: ''
    type: api
"""
    with pytest.raises(ValueError):
        parse_system(yaml_text)


def test_parse_data_flows_and_boundaries(benchmarks_dir):
    sys_ = load_system(benchmarks_dir / "iot_device.yaml")
    assert any(b.name == "rf_field" for b in sys_.trust_boundaries)
    assert any(f.source == "field_node" for f in sys_.data_flows)
