# Eval results

Live numbers from `python eval/run_eval.py` over the 5 expert-curated
benchmarks in `eval/benchmarks/`.

## Method

Each benchmark is a `<name>.yaml` system description plus a sidecar
`<name>.expected.json` listing `(component, STRIDE-letter)` pairs an
experienced reviewer would expect to see flagged. The harness:

1. Runs the rules-only modeller on the YAML.
2. Projects the produced ThreatModel into the same
   `(component, STRIDE-letter)` set.
3. Computes precision / recall / F1 against the expected set, with
   universe = (components × 6 STRIDE categories).

The eval is offline-only and deterministic.

## Reproducing

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python eval/run_eval.py
```

## Latest measured numbers (5 benchmarks, 2026-05-06)

### Aggregate (micro-averaged)

| Metric    | Value     |
| --------- | --------: |
| TP        | 111       |
| FP        | 21        |
| FN        | 0         |
| TN        | 0         |
| Accuracy  | 0.8409    |
| Precision | **0.8409**|
| Recall    | **1.0000**|
| F1        | **0.9136**|

### Per-benchmark

| Benchmark        | n components | universe | TP | FP | FN | Precision | Recall | F1     |
|------------------|-------------:|---------:|---:|---:|---:|----------:|-------:|-------:|
| api_gateway      | 4            | 24       | 22 |  2 |  0 | 0.9167    | 1.0000 | 0.9565 |
| iot_device       | 4            | 24       | 19 |  5 |  0 | 0.7917    | 1.0000 | 0.8837 |
| microservices    | 6            | 36       | 30 |  6 |  0 | 0.8333    | 1.0000 | 0.9091 |
| mobile_app       | 4            | 24       | 21 |  3 |  0 | 0.8750    | 1.0000 | 0.9333 |
| web_app          | 4            | 24       | 19 |  5 |  0 | 0.7917    | 1.0000 | 0.8837 |

## Reading the numbers

* **Recall is perfect** by construction. The catalogue covers all six
  STRIDE categories for every supported component_type, so for any
  pair an expert flagged we will emit at least one threat. The
  question is not "did we miss anything" — it's "did we emit too
  much".

* **Precision is 0.84** because the catalogue is exhaustive
  by design. Shostack's recommendation in chapter 3 is to walk every
  component through every STRIDE category as a checklist; we do
  that, and the expert labels are conservative ("what would I
  bother to mention in a real engagement"). The 21 FPs are pairs
  the catalogue emitted that the expert chose not to label — for
  example, repudiation on an external payment provider (the
  audit-trail responsibility lives with the provider, not the
  integrator).

* **TN is 0** across every benchmark because observed = universe in
  the rules-only mode. As a corollary, accuracy collapses to
  TP / universe and is numerically identical to precision here.
  When an LLM augmentation step adds threats outside the universe
  (e.g., a category the catalogue didn't cover for a custom
  component type), TN > 0 is possible.

## Honest residuals

The 21 false-positive `(component, STRIDE-letter)` pairs are visible
in `eval_summary.json` under `fp_fn_detail`. They cluster around:

* Repudiation on external services (5 FPs) — the integrator can
  log outbound calls but cannot meaningfully audit the third
  party's behaviour.
* Denial of service on infrequently-called or low-traffic
  components (6 FPs) — the catalogue still emits its DoS rule
  even when the expert does not consider DoS a meaningful concern.
* Spoofing on storage and database tiers when the network
  boundary already enforces the identity (4 FPs).

We deliberately do *not* tune the catalogue against these labels.
The catalogue's design goal is to be a complete checklist; the
expert's job in production is to triage. The eval's job is to
quantify how much triage is required.

## What this eval does *not* claim

* It does not measure the optional LLM-augmentation path. The
  augmentation is supported (Anthropic Claude or local Ollama) but
  not benchmarked, mirroring the honest stance of the companion
  ai-governance-checker repo.
* It does not assert the catalogue is complete. Five benchmarks is
  not a comprehensive sample of the threat-modelling literature.
* It does not validate severity bands. The five-band severity scale
  is a heuristic prior, not a quantitative risk score; evaluating
  whether a CRITICAL is more dangerous than a HIGH is outside the
  corpus.
