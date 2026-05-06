# Ethical use

This tool generates a *first-pass* threat model from a YAML system
description. It is meant to give an engineer a starting point, not
to replace a security engineer.

## What this tool does

* Parses a YAML file describing a system (components, trust
  boundaries, data flows, external entities) into a validated
  Pydantic schema.
* Runs a deterministic rule-based STRIDE engine that emits a small
  set of category-appropriate threats per component type. The
  catalogue is conservative and based on Shostack's *Threat
  Modeling: Designing for Security* (Wiley, 2014) and the
  Microsoft STRIDE methodology.
* Optionally augments the rule output by sending the same description
  to Anthropic Claude or a local Ollama model for additional
  category-appropriate threats. Absent any LLM provider, the tool
  produces only the deterministic rule output.
* Renders the result as Markdown and as JSON compatible with the
  OWASP Threat Dragon v2 schema so a security engineer can import
  the model into a real diagramming tool.

## What this tool does not do

* It does **not** produce a complete threat model. The deterministic
  catalogue and any LLM augmentation are starting points; a human
  reviewer must triage, validate, and extend the output. We do not
  attempt to enumerate every possible threat for every component.
* It does **not** assess actual risk. Severity bands in the output
  are heuristic priors, not quantitative risk values.
* It does **not** evaluate countermeasures, residual risk, or
  compensating controls. Those belong in the human-led review that
  follows.
* It does **not** redistribute Anthropic, Ollama, or any other
  vendor's model weights or proprietary content.

## Authorised use only

By using this software you affirm that:

1. You have authority to threat-model the system you describe.
2. You will not present the tool's raw output as a finished threat
   model. The output is an aid; treat it as a draft, never a final
   artefact.
3. You will respect the rate limits of any upstream LLM you point
   the optional augmentation step at.
4. If you redistribute the tool, you keep this file and carry the
   same restrictions through.

## Framework attributions

* OWASP Threat Dragon — © OWASP Foundation, MIT licensed; the JSON
  schema implemented here matches the v2 specification at
  <https://www.threatdragon.com/>.
* STRIDE methodology — originally Microsoft (Hernan, Lambert, Ostwald,
  & Shostack, 2006); extensively documented in Shostack (2014).
* LINDDUN privacy threat analysis — Deng, Wuyts, Scandariato, Preneel,
  Joosen (Requirements Engineering Journal, 2011). Referenced for
  context; not currently encoded in the rule catalogue.

This software is provided as-is under the MIT license. The license
does not override the ethical and legal expectations above; the two
stand together.
