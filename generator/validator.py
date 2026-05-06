"""Pydantic v2 schema for the produced ThreatModel.

The ThreatModel is the *output* contract — the modeller produces it,
the formatter consumes it. A round-trip
``ThreatModel.model_dump_json(...)`` then ``ThreatModel.model_validate_json(...)``
is exercised in the test suite to guard the schema."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrideCategory(str, Enum):
    """The six STRIDE categories (Shostack 2014)."""
    SPOOFING                = "spoofing"
    TAMPERING               = "tampering"
    REPUDIATION             = "repudiation"
    INFORMATION_DISCLOSURE  = "information_disclosure"
    DENIAL_OF_SERVICE       = "denial_of_service"
    ELEVATION_OF_PRIVILEGE  = "elevation_of_privilege"


class Severity(str, Enum):
    """Five-band qualitative severity."""
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Threat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat_id:       str   = Field(..., min_length=1,
                                    description="Stable id, "
                                    "e.g. 'web_frontend.S.session_fixation'")
    component:       str   = Field(..., min_length=1)
    component_type:  str   = Field(..., min_length=1)
    stride_category: StrideCategory
    title:           str   = Field(..., min_length=1)
    description:     str   = Field(..., min_length=1)
    recommendation:  str   = Field(..., min_length=1)
    severity:        Severity = Severity.MEDIUM
    source:          str   = Field(default="rules",
                                    description="'rules', 'anthropic', or 'ollama'")
    references:      list[str] = Field(default_factory=list)


class ThreatModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_name:    str   = Field(..., min_length=1)
    generated_at:   str   = Field(default_factory=lambda: _utcnow_iso())
    threats:        list[Threat] = Field(default_factory=list)
    augmentation:   dict[str, Any] = Field(default_factory=dict,
                                             description="Provenance of "
                                             "any LLM-augmentation step")

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    def by_component(self) -> dict[str, list[Threat]]:
        out: dict[str, list[Threat]] = {}
        for t in self.threats:
            out.setdefault(t.component, []).append(t)
        return out

    def by_category(self) -> dict[str, list[Threat]]:
        out: dict[str, list[Threat]] = {}
        for t in self.threats:
            key = (t.stride_category.value
                    if hasattr(t.stride_category, "value")
                    else t.stride_category)
            out.setdefault(key, []).append(t)
        return out


def _utcnow_iso() -> str:
    """ISO-8601 UTC, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
