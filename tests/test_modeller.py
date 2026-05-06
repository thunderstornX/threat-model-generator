"""Tests for the modeller orchestrator and LLM-augmentation paths."""
from __future__ import annotations

import httpx
import respx

from generator.modeller import (
    _normalise_severity,
    _parse_augment_reply,
    _strip_code_fences,
    model_system,
)
from generator.parser import Component, ComponentType, SystemDescription
from generator.validator import Severity


def _system() -> SystemDescription:
    return SystemDescription(
        name="X",
        components=[
            Component(name="web", type=ComponentType.WEB_FRONTEND),
            Component(name="api", type=ComponentType.API),
        ],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_strip_code_fences_handles_json_block():
    assert _strip_code_fences('```json\n{"a":1}\n```') == '{"a":1}'


def test_strip_code_fences_passthrough():
    assert _strip_code_fences("no fences") == "no fences"


def test_normalise_severity_recognises_aliases():
    assert _normalise_severity("crit") == Severity.CRITICAL
    assert _normalise_severity("HIGH") == Severity.HIGH
    assert _normalise_severity("med") == Severity.MEDIUM
    assert _normalise_severity("nope") == Severity.MEDIUM


def test_parse_augment_drops_unknown_components():
    """The modeller MUST refuse threats that name components the
    system description didn't declare. This is the anti-hallucination
    backstop."""
    body = ('{"threats":[{"component":"hallucinated","stride":"S",'
             '"title":"X","description":"Y","recommendation":"Z",'
             '"severity":"high"}]}')
    assert _parse_augment_reply(body, {"web", "api"}, "anthropic") == []


def test_parse_augment_keeps_known_components():
    body = ('{"threats":[{"component":"web","stride":"S","title":"T",'
             '"description":"D","recommendation":"R","severity":"high"}]}')
    out = _parse_augment_reply(body, {"web", "api"}, "anthropic")
    assert len(out) == 1
    assert out[0].component == "web"
    assert out[0].source == "anthropic"


def test_parse_augment_skips_invalid_stride_letter():
    body = ('{"threats":[{"component":"web","stride":"Z","title":"T",'
             '"description":"D","recommendation":"R"}]}')
    assert _parse_augment_reply(body, {"web"}, "anthropic") == []


def test_parse_augment_handles_garbage_json():
    assert _parse_augment_reply("not json", {"web"}, "anthropic") == []


# ---------------------------------------------------------------------------
# model_system() dispatch
# ---------------------------------------------------------------------------

def test_model_system_rules_only_path(settings_no_keys):
    model = model_system(_system(), settings=settings_no_keys,
                          augment_with_llm=False)
    # 2 components × 6 categories × ≥1 rule each.
    assert model.threat_count >= 12
    assert all(t.source == "rules" for t in model.threats)
    assert model.augmentation == {"requested": False}


def test_model_system_augment_disabled_when_no_provider(settings_no_keys):
    """augment_with_llm=True with no provider available -> rules-only,
    augmentation block records 'disabled'."""
    model = model_system(_system(), settings=settings_no_keys,
                          augment_with_llm=True)
    assert all(t.source == "rules" for t in model.threats)
    assert model.augmentation["status"] == "disabled"
    assert model.augmentation["added"] == 0


def test_model_system_uses_anthropic_when_key_present(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            return_value=httpx.Response(200, json={
                "content": [{"type": "text", "text": (
                    '{"threats":[{"component":"web","stride":"I",'
                    '"title":"Console error leak",'
                    '"description":"D","recommendation":"R",'
                    '"severity":"low"}]}'
                )}],
            })
        )
        model = model_system(_system(), settings=settings_anthropic,
                              augment_with_llm=True)
    extra = [t for t in model.threats if t.source == "anthropic"]
    assert len(extra) == 1
    assert extra[0].component == "web"
    assert model.augmentation["provider"] == "anthropic"
    assert model.augmentation["added"] == 1


def test_model_system_anthropic_http_error(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            return_value=httpx.Response(401, text="bad key"))
        model = model_system(_system(), settings=settings_anthropic,
                              augment_with_llm=True)
    # Catalogue threats unaffected; augmentation block records the 401.
    assert all(t.source == "rules" for t in model.threats)
    assert model.augmentation["status"] == "http_error"
    assert model.augmentation["http_status"] == 401


def test_model_system_anthropic_network_error(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            side_effect=httpx.ConnectError("simulated"))
        model = model_system(_system(), settings=settings_anthropic,
                              augment_with_llm=True)
    assert model.augmentation["status"] == "network_error"
    assert "ConnectError" in model.augmentation["error"]


def test_model_system_uses_ollama_when_anthropic_absent(settings_ollama):
    tags_url = (f"{settings_ollama.ollama_base_url.rstrip('/')}/api/tags")
    chat_url = (f"{settings_ollama.ollama_base_url.rstrip('/')}/api/chat")
    with respx.mock(assert_all_called=False) as router:
        router.get(tags_url).mock(return_value=httpx.Response(
            200, json={"models": []}))
        router.post(chat_url).mock(return_value=httpx.Response(
            200, json={"message": {"content": (
                '{"threats":[{"component":"api","stride":"D","title":"T",'
                '"description":"D","recommendation":"R","severity":"low"}]}'
            )}}))
        model = model_system(_system(), settings=settings_ollama,
                              augment_with_llm=True)
    extra = [t for t in model.threats if t.source == "ollama"]
    assert len(extra) == 1
    assert model.augmentation["provider"] == "ollama"
