<!-- markdownlint-disable MD033 MD041 -->

```
  ████████╗███╗   ███╗ ██████╗
  ╚══██╔══╝████╗ ████║██╔════╝          ─── threat-model-generator ───
     ██║   ██╔████╔██║██║  ███╗
     ██║   ██║╚██╔╝██║██║   ██║         STRIDE   ·   YAML in
     ██║   ██║ ╚═╝ ██║╚██████╔╝         Markdown · Threat Dragon out
     ╚═╝   ╚═╝     ╚═╝ ╚═════╝
```

[![Tests](https://img.shields.io/badge/pytest-61%2F61%20passing-brightgreen)](#testing)
[![Bandit](https://img.shields.io/badge/bandit-0%20issues-brightgreen)](results/security_scan.md)
[![pip-audit](https://img.shields.io/badge/pip--audit-0%20vulns-brightgreen)](results/security_scan.md)
[![Semgrep](https://img.shields.io/badge/semgrep-0%20findings-brightgreen)](results/security_scan.md)
[![Eval F1](https://img.shields.io/badge/F1%20%28rules--only%29-0.9136-brightgreen)](results/README.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20480460.svg)](https://doi.org/10.5281/zenodo.20480460)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
`threat-model-generator` reads a YAML system description and emits a
**STRIDE threat model** in two formats: a human-readable Markdown
report and a JSON document compatible with the
[OWASP Threat Dragon v2 schema](https://www.threatdragon.com/).

The deterministic rules-only mode runs offline with no API keys,
covers nine component types × six STRIDE categories, and is
fully reproducible. An optional `--augment-with-llm` step routes
the description to Anthropic Claude or a local Ollama model with
three-step graceful fallback if no provider is reachable.

## Quick start

```bash
git clone https://github.com/thunderstornX/threat-model-generator.git
cd threat-model-generator

python -m venv .venv
.venv/bin/pip install -r requirements.txt

# Generate Markdown + Threat Dragon JSON for a benchmark system:
.venv/bin/python -m cli.main \
    --input eval/benchmarks/web_app.yaml \
    --output out/web_app

# Markdown only:
.venv/bin/python -m cli.main \
    --input eval/benchmarks/iot_device.yaml \
    --output out/iot.md \
    --format markdown

# Optional LLM augmentation (graceful fallback if no provider):
.venv/bin/python -m cli.main \
    --input eval/benchmarks/web_app.yaml \
    --output out/web_app --augment-with-llm
```

CLI status output:

```
[*] threat-model: 'ExampleShop' (4 components)
[*] augmentation: disabled (rules-only)
[+] 24 threat(s) generated
[+] wrote (markdown) out/web_app.md
[+] wrote (threatdragon) out/web_app.json
```

## YAML schema

```yaml
name: MySystem
description: One-line system summary
components:
  - name: web_frontend_1
    type: web_frontend       # web_frontend | api | database | queue |
                             # storage | auth_service | mobile_client |
                             # iot_device | external_service
    sensitivity: confidential   # public | internal | confidential | restricted
    description: Optional component description
trust_boundaries:
  - name: dmz
    inside: [web_frontend_1]
data_flows:
  - source: web_frontend_1
    destination: api_1
    protocol: HTTPS
    sensitivity: confidential
external_entities:
  - name: customer
    description: End user
```

The schema is validated by Pydantic v2; unknown fields are rejected
at load time. Component names must be unique within a description.

## Architecture

```
                ┌──────────────────────┐
                │ parser (YAML)        │  Pydantic-validated, strict
                └──────────────────────┘
                            │
                ┌───────────┴──────────┐
                │ STRIDE rule catalogue│  9 component types × 6 categories
                │ (deterministic)      │  ≥54 entries; cites Shostack 2014
                └───────────┬──────────┘
                            │              optional graceful fallback
                ┌───────────┴──────────┐  ┌─────────────────────┐
                │ modeller             │←─│ LLM augmenter        │
                │                      │  │ Anthropic → Ollama   │
                │                      │  │ → DISABLED           │
                └───────────┬──────────┘  └─────────────────────┘
                            │
                ┌───────────┴──────────┐
                │ formatter            │
                │   • Markdown report  │
                │   • Threat Dragon v2 │
                └──────────────────────┘
```

The augmenter applies two anti-hallucination guards: any threat
naming a component that the system description did not declare is
dropped, and any threat with an unrecognised STRIDE letter is
dropped.

## Reproducing the eval

```bash
.venv/bin/python eval/run_eval.py
```

Runs all 5 expert-curated benchmarks against the rules-only
modeller and writes:

* `results/eval_summary.json` — aggregate + per-benchmark metrics
* `results/eval_raw.csv` — per-benchmark observations

**Latest measured numbers** (rules-only, 2026-05-06):

| Benchmark        | n components | Precision | Recall | F1     |
|------------------|-------------:|----------:|-------:|-------:|
| api_gateway      | 4            | 0.9167    | 1.0000 | 0.9565 |
| iot_device       | 4            | 0.7917    | 1.0000 | 0.8837 |
| microservices    | 6            | 0.8333    | 1.0000 | 0.9091 |
| mobile_app       | 4            | 0.8750    | 1.0000 | 0.9333 |
| web_app          | 4            | 0.7917    | 1.0000 | 0.8837 |
| **Aggregate (micro)** | **22**  | **0.8409**| **1.0000** | **0.9136** |

Recall is perfect by construction (catalogue covers all 6 STRIDE
categories for every component type). Precision is 0.84 because the
catalogue is exhaustive — it deliberately emits one threat per
(component, category) pair even when an experienced reviewer would
not bother to mention some of them. See
[results/README.md](results/README.md) for the FP-cluster analysis
and what we deliberately did *not* tune.

## Testing

```bash
.venv/bin/pytest -q
```

61 tests across the parser, the rule catalogue, the modeller (all
three augmentation paths), the validator, the formatter, and the
eval harness. HTTP is mocked with
[`respx`](https://lundberg.github.io/respx/).

| Module                  | Tests |
|-------------------------|------:|
| `stride_rules.py`       | 17    |
| `modeller.py`           | 13    |
| `parser.py`             | 9     |
| `formatter.py`          | 8     |
| `validator.py`          | 7     |
| `eval/run_eval.py`      | 7     |
| **Total**               | **61**|

## Security posture

| Gate       | Findings | Suppressions |
|-----------:|:--------:|:------------:|
| Bandit     | 0        | 0            |
| pip-audit  | 0        | 0            |
| Semgrep    | 0        | 0            |

See [results/security_scan.md](results/security_scan.md).

## What this tool does *not* do

* It does **not** produce a complete threat model. The catalogue
  and any LLM augmentation are starting points; a human reviewer
  must triage, validate, and extend.
* It does **not** assess actual risk. Severity bands are heuristic
  priors, not quantitative risk values.
* It does **not** evaluate countermeasures or residual risk.

See [ETHICAL_USE.md](ETHICAL_USE.md) for the full ethical-use
statement.

## Citing

If you use this software in academic work, please cite the
[CITATION.cff](CITATION.cff) record. The companion
[IEEE paper](paper/paper.tex) describes the design and reports the
live measurements.

## License

MIT. See [LICENSE](LICENSE).
