"""threat-model-generator: STRIDE threat modelling from YAML system descriptions.

Public submodules:
    parser       — load & validate a YAML SystemDescription
    stride_rules — deterministic per-component-type STRIDE catalogue
    modeller     — orchestrator (rules-only or rules + LLM augmentation)
    validator    — Pydantic v2 schema for the produced ThreatModel
    formatter    — Markdown + OWASP Threat Dragon v2 JSON output
"""
from .parser import (
    Component,
    ComponentType,
    DataFlow,
    ExternalEntity,
    SystemDescription,
    Sensitivity,
    TrustBoundary,
    load_system,
)
from .validator import (
    Threat,
    ThreatModel,
    StrideCategory,
    Severity,
)

__all__ = [
    "Component", "ComponentType", "DataFlow", "ExternalEntity",
    "SystemDescription", "Sensitivity", "TrustBoundary", "load_system",
    "Threat", "ThreatModel", "StrideCategory", "Severity",
]
