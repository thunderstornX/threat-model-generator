"""YAML system-description parser with Pydantic validation.

A SystemDescription is the input contract for the threat-model engine.
It is intentionally small — four lists (components, trust_boundaries,
data_flows, external_entities) — because every additional field is a
dial the operator must understand. The component_type enum is the
join key with the STRIDE rule catalogue: every value here must have
a corresponding rule entry in stride_rules.py.

Schema deliberately permissive on optional fields, strict on the
ones the rule engine relies on: name, type, sensitivity."""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class ComponentType(str, Enum):
    """The join key with stride_rules.py — every value here MUST have
    a corresponding rule set in the catalogue."""
    WEB_FRONTEND     = "web_frontend"
    API              = "api"
    DATABASE         = "database"
    QUEUE            = "queue"
    STORAGE          = "storage"
    AUTH_SERVICE     = "auth_service"
    MOBILE_CLIENT    = "mobile_client"
    IOT_DEVICE       = "iot_device"
    EXTERNAL_SERVICE = "external_service"


class Sensitivity(str, Enum):
    """Data-sensitivity band influencing severity in the rule output."""
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED   = "restricted"


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1)
    type: ComponentType
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    description: str | None = None


class TrustBoundary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1)
    inside: list[str] = Field(default_factory=list,
                                description="Component names inside this boundary")
    description: str | None = None


class DataFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(..., min_length=1)
    destination: str = Field(..., min_length=1)
    protocol: str | None = None
    sensitivity: Sensitivity = Sensitivity.INTERNAL


class ExternalEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1)
    description: str | None = None


class SystemDescription(BaseModel):
    """The full input document."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, description="System name")
    description: str | None = None
    components: list[Component] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    external_entities: list[ExternalEntity] = Field(default_factory=list)

    @field_validator("components")
    @classmethod
    def _at_least_one_component(cls, v):
        if not v:
            raise ValueError("system description must have at least one component")
        return v

    @field_validator("components")
    @classmethod
    def _component_names_unique(cls, v):
        names = [c.name for c in v]
        if len(names) != len(set(names)):
            dupes = sorted({n for n in names if names.count(n) > 1})
            raise ValueError(f"duplicate component name(s): {dupes}")
        return v


def load_system(path: str | Path) -> SystemDescription:
    """Load a YAML system description from disk and validate it."""
    raw = Path(path).read_text(encoding="utf-8")
    return parse_system(raw)


def parse_system(raw: str) -> SystemDescription:
    """Parse a YAML *string* into a SystemDescription."""
    data: Any = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("system description must be a YAML mapping at the top level")
    try:
        return SystemDescription.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"system description failed validation: {exc}") from exc
