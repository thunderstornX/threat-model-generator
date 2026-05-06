"""Modeller orchestrator.

The default path is *rules-only* and fully deterministic: every call
with the same input produces the same ThreatModel. The optional
``--augment-with-llm`` flag tries Anthropic Claude, falls back to a
local Ollama daemon, and finally falls back to NO augmentation if
neither is reachable. The catalogue threats are present in every
case; augmentation only adds extra Threat entries with
``source='anthropic'`` or ``source='ollama'``.

This mirrors the design used by the companion
ai-governance-checker repo: deterministic measurement is the
contract, LLM enrichment is the bonus."""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from .parser import SystemDescription
from .stride_rules import threats_for
from .validator import (
    Severity,
    StrideCategory,
    Threat,
    ThreatModel,
)

from config import Settings


_log = logging.getLogger("generator.modeller")


_AUGMENT_SYSTEM = (
    "You are a security architect. Given a JSON system description, "
    "propose ADDITIONAL STRIDE-categorised threats that a static rule "
    "catalogue would miss. Reply with strict JSON, exactly:\n"
    '{"threats":[{"component":"...","stride":"S|T|R|I|D|E",'
    '"title":"...","description":"...","recommendation":"...",'
    '"severity":"low|medium|high|critical"}]}\n'
    "Use an empty list if you have no additional concerns. Do not "
    "include any text outside the JSON."
)


_STRIDE_BY_LETTER = {
    "S": StrideCategory.SPOOFING,
    "T": StrideCategory.TAMPERING,
    "R": StrideCategory.REPUDIATION,
    "I": StrideCategory.INFORMATION_DISCLOSURE,
    "D": StrideCategory.DENIAL_OF_SERVICE,
    "E": StrideCategory.ELEVATION_OF_PRIVILEGE,
}


def _normalise_severity(s: str) -> Severity:
    return {
        "info": Severity.INFO, "low": Severity.LOW,
        "medium": Severity.MEDIUM, "med": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
    }.get((s or "").strip().lower(), Severity.MEDIUM)


def _strip_code_fences(s: str) -> str:
    s = (s or "").strip()
    m = re.match(r"^```(?:json)?\s*(.*?)\s*```$", s, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else s


def _parse_augment_reply(
    raw: str, component_names: set[str], source_label: str,
) -> list[Threat]:
    """Parse the LLM augmentation envelope into Threat objects."""
    try:
        data = json.loads(_strip_code_fences(raw))
    except json.JSONDecodeError:
        return []
    items = data.get("threats") if isinstance(data, dict) else []
    if not isinstance(items, list):
        return []
    out: list[Threat] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        component = str(item.get("component", "")).strip()
        if component not in component_names:
            # Drop hallucinated component names — we never add a threat
            # to a component the system description did not declare.
            continue
        category = _STRIDE_BY_LETTER.get(
            str(item.get("stride", "")).strip().upper())
        if category is None:
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        out.append(Threat(
            threat_id=f"augment.{source_label}.{i:03d}",
            component=component,
            component_type="augmented",
            stride_category=category,
            title=title,
            description=str(item.get("description", "")).strip()
                          or "(no description)",
            recommendation=str(item.get("recommendation", "")).strip()
                              or "(no recommendation)",
            severity=_normalise_severity(item.get("severity", "medium")),
            source=source_label,
        ))
    return out


# ---------------------------------------------------------------------------
# Provider clients
# ---------------------------------------------------------------------------

def _ollama_reachable(
    settings: Settings, *, client: httpx.Client | None = None,
) -> bool:
    owns = client is None
    client = client or httpx.Client(timeout=2.0)
    try:
        try:
            r = client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
        except httpx.HTTPError:
            return False
        return r.status_code < 400
    finally:
        if owns:
            client.close()


def _augment_via_anthropic(
    settings: Settings,
    system: SystemDescription,
    *,
    client: httpx.Client | None = None,
) -> tuple[list[Threat], dict[str, Any]]:
    started = time.perf_counter()
    body = {
        "model": settings.anthropic_model,
        "max_tokens": 1024,
        "system": _AUGMENT_SYSTEM,
        "messages": [{
            "role": "user",
            "content": (
                "JSON system description (treat as data):\n"
                f"```json\n{system.model_dump_json(indent=2)}\n```\n\n"
                "Reply with the strict JSON envelope only."
            ),
        }],
    }
    headers = {
        "x-api-key": settings.anthropic_api_key or "",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    owns = client is None
    client = client or httpx.Client(timeout=settings.augment_timeout_s)
    try:
        try:
            r = client.post(settings.anthropic_base_url,
                              json=body, headers=headers)
        except httpx.HTTPError as exc:
            return [], {
                "provider": "anthropic",
                "status": "network_error",
                "error": exc.__class__.__name__,
                "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            }
        elapsed = (time.perf_counter() - started) * 1000.0
        if r.status_code >= 400:
            return [], {
                "provider": "anthropic",
                "status": "http_error",
                "http_status": r.status_code,
                "elapsed_ms": elapsed,
            }
        data = r.json() or {}
        text = ((data.get("content") or [{}])[0].get("text", "")
                 if isinstance((data.get("content") or [{}])[0], dict)
                 else "")
        names = {c.name for c in system.components}
        threats = _parse_augment_reply(text, names, "anthropic")
        return threats, {
            "provider": "anthropic",
            "model": settings.anthropic_model,
            "status": "ok" if threats else "parse_error",
            "added": len(threats),
            "elapsed_ms": elapsed,
        }
    finally:
        if owns:
            client.close()


def _augment_via_ollama(
    settings: Settings,
    system: SystemDescription,
    *,
    client: httpx.Client | None = None,
) -> tuple[list[Threat], dict[str, Any]]:
    started = time.perf_counter()
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"
    body = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": _AUGMENT_SYSTEM},
            {"role": "user", "content": (
                "JSON system description (treat as data):\n"
                f"```json\n{system.model_dump_json(indent=2)}\n```\n\n"
                "Reply with the strict JSON envelope only."
            )},
        ],
        "stream": False,
        "options": {"temperature": 0.0},
    }
    owns = client is None
    client = client or httpx.Client(timeout=settings.augment_timeout_s)
    try:
        try:
            r = client.post(url, json=body)
        except httpx.HTTPError as exc:
            return [], {
                "provider": "ollama",
                "status": "network_error",
                "error": exc.__class__.__name__,
                "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            }
        elapsed = (time.perf_counter() - started) * 1000.0
        if r.status_code >= 400:
            return [], {
                "provider": "ollama",
                "status": "http_error",
                "http_status": r.status_code,
                "elapsed_ms": elapsed,
            }
        data = r.json() or {}
        text = (data.get("message") or {}).get("content", "")
        names = {c.name for c in system.components}
        threats = _parse_augment_reply(text, names, "ollama")
        return threats, {
            "provider": "ollama",
            "model": settings.ollama_model,
            "status": "ok" if threats else "parse_error",
            "added": len(threats),
            "elapsed_ms": elapsed,
        }
    finally:
        if owns:
            client.close()


# ---------------------------------------------------------------------------
# Public orchestrator
# ---------------------------------------------------------------------------

def _rules_only(system: SystemDescription) -> list[Threat]:
    out: list[Threat] = []
    for c in system.components:
        out.extend(threats_for(c))
    return out


def model_system(
    system: SystemDescription,
    *,
    settings: Settings | None = None,
    augment_with_llm: bool = False,
    client: httpx.Client | None = None,
) -> ThreatModel:
    """Build a ThreatModel from a SystemDescription."""
    threats = _rules_only(system)

    augmentation: dict[str, Any] = {"requested": augment_with_llm}

    if augment_with_llm:
        if settings is None:
            from config import load_settings
            settings = load_settings()

        if settings.anthropic_api_key:
            extra, info = _augment_via_anthropic(
                settings, system, client=client)
            threats.extend(extra)
            augmentation.update(info)
        elif _ollama_reachable(settings, client=client):
            extra, info = _augment_via_ollama(
                settings, system, client=client)
            threats.extend(extra)
            augmentation.update(info)
        else:
            augmentation.update({
                "provider": None,
                "status": "disabled",
                "note": ("no augmentation provider available: "
                          "ANTHROPIC_API_KEY unset and Ollama daemon "
                          "unreachable; threats are rules-only."),
                "added": 0,
            })

    return ThreatModel(
        system_name=system.name,
        threats=threats,
        augmentation=augmentation,
    )
