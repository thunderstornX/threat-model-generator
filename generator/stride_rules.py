"""Deterministic STRIDE rule catalogue.

For each ComponentType, this module knows a small, conservative set
of category-appropriate threats. The catalogue is *intentionally*
small: the goal is not to enumerate every possible threat (no static
catalogue can), but to give a reviewer a credible starting point
they can confirm or extend.

Severity bumping rule
---------------------
A component's *Sensitivity* shifts the default severity by one band:
  RESTRICTED   -> +1 band (medium becomes high, high becomes critical)
  CONFIDENTIAL -> +0 bands (use the catalogue default)
  INTERNAL     -> +0 bands
  PUBLIC       -> -1 band (high becomes medium, etc.)
This is a heuristic prior, not a quantitative risk score. The
ETHICAL_USE.md is explicit about this.

Provenance
----------
The catalogue is informed by Shostack's *Threat Modeling: Designing
for Security* (Wiley, 2014) — chapter 3 (STRIDE) and chapter 4
(attack libraries) — and by the Microsoft STRIDE methodology of
Hernan, Lambert, Ostwald, and Shostack (IEEE Security & Privacy,
2006). Specific threat wording is paraphrased to fit a one-paragraph
description; we do not redistribute prose from the cited sources."""
from __future__ import annotations

from .parser import Component, ComponentType, Sensitivity
from .validator import Severity, StrideCategory, Threat


# ---------------------------------------------------------------------------
# Severity-band arithmetic
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: list[Severity] = [
    Severity.INFO, Severity.LOW, Severity.MEDIUM,
    Severity.HIGH, Severity.CRITICAL,
]


def _shift_severity(base: Severity, delta: int) -> Severity:
    """Move severity by ``delta`` bands, clamped to the enum."""
    idx = _SEVERITY_ORDER.index(base) + delta
    idx = max(0, min(idx, len(_SEVERITY_ORDER) - 1))
    return _SEVERITY_ORDER[idx]


def _sensitivity_delta(s: Sensitivity) -> int:
    return {
        Sensitivity.RESTRICTED:    +1,
        Sensitivity.CONFIDENTIAL:   0,
        Sensitivity.INTERNAL:       0,
        Sensitivity.PUBLIC:        -1,
    }.get(s, 0)


# ---------------------------------------------------------------------------
# Rule catalogue: one entry per (ComponentType, StrideCategory)
# ---------------------------------------------------------------------------

# Each entry is (slug, title, description, recommendation, base_severity).
# Slug becomes the trailing piece of threat_id (e.g.
# "web_frontend.S.session_fixation").
_Rule = tuple[str, str, str, str, Severity]


_CATALOGUE: dict[ComponentType, dict[StrideCategory, list[_Rule]]] = {
    ComponentType.WEB_FRONTEND: {
        StrideCategory.SPOOFING: [(
            "session_fixation",
            "Session fixation lets attackers hijack authenticated sessions",
            "If session IDs are accepted from URL params or honoured "
            "across login boundaries, an attacker who plants a known "
            "session ID can impersonate the user post-login.",
            "Rotate the session ID at every authentication transition; "
            "set Secure / HttpOnly / SameSite cookies; never accept "
            "session IDs from query strings.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "stored_xss",
            "Reflected and stored XSS in user-supplied fields",
            "User-supplied content rendered into the DOM without "
            "context-aware encoding allows an attacker to execute "
            "script in another user's session.",
            "Use a templating engine that auto-escapes by context "
            "(HTML, attribute, JS, URL); set a strict Content-Security-"
            "Policy; never inject untrusted strings into innerHTML.",
            Severity.HIGH,
        )],
        StrideCategory.REPUDIATION: [(
            "missing_audit_log",
            "Authenticated user actions are not server-side audit-logged",
            "If consequential actions (password change, role grant, "
            "data export) are not logged with a tamper-evident "
            "user/action/timestamp tuple, a compromised account's "
            "actions cannot be reconstructed after-the-fact.",
            "Log every state-changing user action server-side with the "
            "session subject; ship logs to an append-only store.",
            Severity.MEDIUM,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "verbose_error_messages",
            "Verbose stack traces or error pages leak implementation detail",
            "Default framework error pages expose stack traces, ORM "
            "queries, internal paths, or library versions to anyone "
            "who can trigger an error.",
            "Configure a generic error page in production; route "
            "stack traces to internal-only logs.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "unbounded_request_body",
            "No request-body size cap allows resource exhaustion",
            "An attacker who can POST arbitrarily large bodies (or "
            "open many concurrent requests) can starve the application "
            "of CPU, memory, or upstream connection budget.",
            "Set explicit request-body size limits at the gateway; "
            "rate-limit per IP and per authenticated subject; queue "
            "fairly under load.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "idor_object_reference",
            "Insecure direct object reference (IDOR) lets users see others' data",
            "If endpoints accept object IDs without authorising the "
            "current user against them, any authenticated user can "
            "iterate the ID space and read or modify others' records.",
            "Authorise every object access against the session "
            "subject; prefer per-user scoped IDs or signed references.",
            Severity.HIGH,
        )],
    },

    ComponentType.API: {
        StrideCategory.SPOOFING: [(
            "weak_token_validation",
            "API accepts unsigned or unverified JWTs",
            "If the API treats the JWT 'alg' header as authoritative, "
            "or skips signature verification entirely, an attacker can "
            "forge tokens for arbitrary subjects.",
            "Pin the expected algorithm server-side; verify signature "
            "against a trusted JWKS; reject 'none' and unexpected algs.",
            Severity.CRITICAL,
        )],
        StrideCategory.TAMPERING: [(
            "mass_assignment",
            "Mass-assignment lets clients set protected fields",
            "If the API binds the entire request body onto the model "
            "without an explicit allow-list, a client can set "
            "'is_admin' or 'tenant_id' fields the schema did not "
            "intend to be writable.",
            "Use explicit DTO classes that name every writable field; "
            "reject unknown keys at deserialisation time.",
            Severity.HIGH,
        )],
        StrideCategory.REPUDIATION: [(
            "no_request_correlation_id",
            "No correlation ID across requests breaks audit reconstruction",
            "Without a request_id propagated end-to-end, a security "
            "incident cannot be reconstructed from logs alone.",
            "Generate a UUIDv4 request_id at the edge; log and "
            "propagate it through every downstream call.",
            Severity.LOW,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "overpermissive_response",
            "API returns more fields than the caller is entitled to",
            "Default ORM serialisation often emits columns (hashed_pw, "
            "internal_id, updated_at_microseconds) that the caller "
            "does not need and that may leak when paired with other "
            "vectors.",
            "Define explicit response schemas; field-by-field opt-in.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "no_rate_limit",
            "No per-subject rate limit allows enumeration and exhaustion",
            "An unauthenticated or low-privileged subject who can call "
            "expensive endpoints without rate limiting can enumerate "
            "the system or exhaust upstream services.",
            "Apply token-bucket rate limits keyed on authenticated "
            "subject (or IP for unauthenticated); document the limits.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "bola",
            "Broken Object-Level Authorisation (OWASP API1)",
            "If endpoints reach into the data store using a "
            "client-supplied id without checking the session "
            "subject's authority over that id, every authenticated "
            "user can act on every other user's resources.",
            "Centralise object-level authorisation in a single "
            "decorator or middleware; deny by default.",
            Severity.CRITICAL,
        )],
    },

    ComponentType.DATABASE: {
        StrideCategory.SPOOFING: [(
            "weak_db_auth",
            "Database accepts username+password from any source IP",
            "A long-lived static credential without IAM-style identity "
            "binding lets a leaked password authorise from anywhere.",
            "Bind DB auth to short-lived IAM tokens (or mTLS) where "
            "supported; restrict source IPs at the network layer.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "sql_injection_surface",
            "String-concatenated SQL surfaces from any caller invite injection",
            "Even one caller that builds queries by string concatenation "
            "is enough to compromise the entire database.",
            "Use parameterised queries everywhere; treat ORM as the "
            "primary path; lint for raw SQL building.",
            Severity.CRITICAL,
        )],
        StrideCategory.REPUDIATION: [(
            "no_db_audit",
            "Database does not emit audit events for privileged actions",
            "Without server-side audit (DDL, role grant, mass DELETE), "
            "a privileged-account compromise cannot be reconstructed.",
            "Enable server-side audit; ship to an append-only store; "
            "alert on schema changes and bulk deletes.",
            Severity.MEDIUM,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "overprivileged_reads",
            "Application service account has read access beyond its need",
            "If the application's DB role can read tables the "
            "application never queries (PII archives, billing), a "
            "single SQLi or compromised credential exposes more than "
            "needed.",
            "Per-role least-privilege; one role per logical "
            "consumer; revoke unused grants.",
            Severity.HIGH,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "connection_flood",
            "No per-source connection cap allows pool exhaustion",
            "A single misbehaving caller can saturate the database "
            "connection pool, locking out every other consumer.",
            "Per-role / per-source connection caps; circuit-break on "
            "saturation; surface metrics.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "shared_admin_role",
            "Application uses a single database admin role for everything",
            "If the application's runtime role is also the schema-"
            "migration role, a compromise of the runtime account is "
            "instantly able to alter the schema and grant new roles.",
            "Separate runtime and migration roles; gate migrations "
            "behind a deploy-time identity, not a runtime one.",
            Severity.CRITICAL,
        )],
    },

    ComponentType.QUEUE: {
        StrideCategory.SPOOFING: [(
            "unauthenticated_publish",
            "Queue accepts publishes without producer identity",
            "Without a producer identity bound to each message, a "
            "compromised neighbour can publish forged events into the "
            "stream.",
            "Require mTLS or signed messages; enforce per-topic "
            "publish ACLs.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "no_message_integrity",
            "Messages can be modified in transit by the broker",
            "If the broker is in a different trust zone and there is "
            "no end-to-end signature, the broker (or anyone with broker "
            "access) can modify the payload.",
            "Sign or HMAC payloads producer-side; verify consumer-side.",
            Severity.MEDIUM,
        )],
        StrideCategory.REPUDIATION: [(
            "no_producer_identity_in_payload",
            "Messages carry no producer identity",
            "When an event causes a downstream incident, the lack of "
            "producer identity makes attribution and rollback hard.",
            "Embed producer identity (and a request correlation id) "
            "in every message envelope.",
            Severity.LOW,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "overbroad_subscriptions",
            "Wildcard subscriptions read more than necessary",
            "A subscriber that wildcards across topics may receive "
            "events it has no business processing.",
            "Per-consumer per-topic ACLs; deny by default; review on "
            "schema changes.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "queue_flood",
            "No per-producer publish rate limit allows queue saturation",
            "A misbehaving producer can saturate the queue and block "
            "every consumer from progressing.",
            "Per-producer rate limits; backpressure to the producer; "
            "alert on dead-letter buildup.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "consumer_runs_with_publisher_role",
            "Single role covers both publish and consume privileges",
            "If a consumer process compromise also implies publish "
            "rights, an attacker can inject events back into the "
            "stream.",
            "Per-direction role separation; runtime principle of "
            "least authority.",
            Severity.HIGH,
        )],
    },

    ComponentType.STORAGE: {
        StrideCategory.SPOOFING: [(
            "presigned_url_replay",
            "Pre-signed URLs replayable by anyone who sees them",
            "Pre-signed URLs leak via logs, browser history, and CDNs; "
            "if the TTL is long, an attacker who scrapes one can "
            "replay it.",
            "Short TTLs (minutes); bind to source IP where possible; "
            "log every issuance.",
            Severity.MEDIUM,
        )],
        StrideCategory.TAMPERING: [(
            "no_object_integrity",
            "Stored objects have no integrity check on read",
            "A compromise of the storage layer or a misconfigured "
            "lifecycle rule can corrupt objects without the consumer "
            "noticing.",
            "Store a server-side checksum and verify on read; consider "
            "object versioning + write-once retention.",
            Severity.MEDIUM,
        )],
        StrideCategory.REPUDIATION: [(
            "no_access_log",
            "Storage layer does not emit per-object access logs",
            "Without per-object access logs, a leak via legitimate-"
            "looking access cannot be proven after the fact.",
            "Enable server-side access logging; ship to append-only.",
            Severity.MEDIUM,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "public_bucket",
            "Bucket policy permits public read",
            "An overly broad bucket policy is the canonical accidental "
            "data exposure path.",
            "Default-deny bucket policy; allow-list named principals; "
            "alert on policy changes.",
            Severity.CRITICAL,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "egress_cost_amplification",
            "An attacker can drive egress charges against the owner",
            "If unauthenticated reads are allowed, an attacker can "
            "replay large objects to drive up the owner's egress "
            "bill (denial-of-wallet).",
            "Authenticate every read; rate-limit; budget alerts on "
            "egress.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "object_acl_bypass",
            "Per-object ACLs bypass the bucket-level deny policy",
            "Per-object ACLs that grant read can override an apparent "
            "bucket-level deny, surprising operators.",
            "Disable object ACLs in favour of bucket-level "
            "policy-only; audit object ACLs on legacy buckets.",
            Severity.HIGH,
        )],
    },

    ComponentType.AUTH_SERVICE: {
        StrideCategory.SPOOFING: [(
            "weak_password_reset",
            "Password reset tokens predictable or reusable",
            "If the reset token is short, sequential, or replayable, "
            "the reset flow is itself the attack surface.",
            "128-bit random tokens; single use; short TTL; bind to "
            "the requested account.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "no_mfa_enrollment_protection",
            "MFA enrolment can be tampered without re-auth",
            "An attacker with a transient session can enrol their own "
            "MFA factor and lock the legitimate user out.",
            "Require step-up auth before MFA enrolment changes; alert "
            "on factor changes.",
            Severity.HIGH,
        )],
        StrideCategory.REPUDIATION: [(
            "no_login_telemetry",
            "Login attempts not telemetered with subject + outcome",
            "Without per-attempt telemetry, password-spraying and "
            "credential-stuffing campaigns are invisible.",
            "Log every authentication attempt; ship to a SIEM; alert "
            "on per-subject failure spikes.",
            Severity.MEDIUM,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "user_enumeration",
            "Login flow leaks whether a username exists",
            "Different error messages or response timings between "
            "'unknown user' and 'wrong password' enumerate the user "
            "namespace.",
            "Constant-time response shape; identical message; "
            "consider unifying with the rate-limit reply.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "lockout_amplification",
            "Per-account lockout can be weaponised against legit users",
            "A naive lockout-after-N-failures policy lets an attacker "
            "who knows usernames lock every legitimate user out.",
            "Lockouts per-IP, not per-account; require captcha + "
            "MFA challenge instead of hard lock.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "session_fixation_post_auth",
            "Session id not rotated at login allows pre-auth fixation",
            "If the session id is the same before and after login, an "
            "attacker who plants one can ride the post-login session.",
            "Rotate the session id at every authentication boundary.",
            Severity.HIGH,
        )],
    },

    ComponentType.MOBILE_CLIENT: {
        StrideCategory.SPOOFING: [(
            "no_cert_pinning",
            "Mobile client trusts the system trust store",
            "Without certificate pinning, a malicious CA on the device "
            "(corporate MITM, stolen profile) can intercept traffic.",
            "Pin to the leaf or intermediate; rotate via a managed "
            "config channel.",
            Severity.MEDIUM,
        )],
        StrideCategory.TAMPERING: [(
            "no_jailbreak_detection",
            "App runs unchanged on jailbroken / rooted devices",
            "On a compromised device, the app's local secrets can be "
            "extracted and its logic altered.",
            "Detect jailbreak indicators; degrade or refuse high-risk "
            "operations; treat the device as adversarial.",
            Severity.MEDIUM,
        )],
        StrideCategory.REPUDIATION: [(
            "no_client_log_signing",
            "Client-emitted telemetry is not signed",
            "Telemetry from a compromised device can be forged to hide "
            "evidence of misuse.",
            "Sign client telemetry with a per-install key; verify "
            "server-side.",
            Severity.LOW,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "logs_to_world_readable_storage",
            "App writes verbose logs to world-readable storage",
            "Writing tokens or PII to /sdcard or the iOS shared "
            "container exposes them to other apps on the device.",
            "Write logs only to app-private storage; redact tokens; "
            "no PII in logs.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "no_offline_handling",
            "App locks up under upstream outage",
            "A blocking network call on the UI thread freezes the app "
            "the moment upstream is slow or down.",
            "All network on background threads; timeouts everywhere; "
            "graceful offline UX.",
            Severity.LOW,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "deeplink_hijack",
            "Deep links accept untrusted parameters",
            "A malicious deep link from a phishing site can trigger "
            "privileged actions (transfer funds, change email) without "
            "user confirmation.",
            "Treat deep-link params as untrusted; require confirmation "
            "for any state-changing action; verify the launch source.",
            Severity.HIGH,
        )],
    },

    ComponentType.IOT_DEVICE: {
        StrideCategory.SPOOFING: [(
            "shared_default_key",
            "Devices ship with a shared default key",
            "If every device of a model carries the same firmware "
            "credential, extracting one device's flash compromises "
            "every device.",
            "Per-device unique keys provisioned at manufacture; bind "
            "device identity to a serial-tied certificate.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "unsigned_ota",
            "OTA updates are not cryptographically signed",
            "Without signed firmware images, anyone in the update "
            "path can ship malware to every device.",
            "Sign firmware with a per-vendor key held offline; verify "
            "signature in the bootloader.",
            Severity.CRITICAL,
        )],
        StrideCategory.REPUDIATION: [(
            "no_device_audit",
            "Device emits no per-event audit records",
            "Constrained devices often skip audit, leaving "
            "field-incidents unreconstructable.",
            "At minimum, emit a tamper-evident counter / boot id; "
            "ship periodically.",
            Severity.LOW,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "rf_metadata_leak",
            "Radio metadata (node id, location) broadcast in clear",
            "Even with encrypted payloads, RF metadata can profile "
            "movement, presence, or relationships.",
            "Anonymous identifiers; rotate on a privacy-preserving "
            "schedule; consider mixnet-style relays.",
            Severity.MEDIUM,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "rf_jamming_susceptible",
            "No fallback when the RF channel is jammed",
            "An adjacent attacker can jam the channel and the device "
            "has no ground-truth way to fall back.",
            "Local-only fallback for safety-critical actions; "
            "anomaly detection on prolonged silence.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "debug_uart_open",
            "Production firmware leaves UART/JTAG debug accessible",
            "Field-extracted devices yield root via debug ports; from "
            "there the attacker reads keys and replays them across "
            "the fleet.",
            "Disable debug ports in production builds; epoxy / fuse "
            "where physical attack is in scope.",
            Severity.HIGH,
        )],
    },

    ComponentType.EXTERNAL_SERVICE: {
        StrideCategory.SPOOFING: [(
            "unauthenticated_webhooks",
            "Inbound webhooks are not authenticated",
            "If we accept inbound webhooks without verifying a signed "
            "header, anyone who learns the URL can forge events.",
            "Verify a vendor-supplied HMAC; reject on signature "
            "mismatch; rotate the secret.",
            Severity.HIGH,
        )],
        StrideCategory.TAMPERING: [(
            "trusted_third_party_input",
            "Third-party data is treated as trusted",
            "Inbound vendor JSON is parsed and acted on without "
            "schema validation, letting a vendor compromise become "
            "our compromise.",
            "Validate every inbound payload against a strict schema; "
            "log and discard fields outside the schema.",
            Severity.MEDIUM,
        )],
        StrideCategory.REPUDIATION: [(
            "no_outbound_audit",
            "Outbound calls to third parties are not audit-logged",
            "When a third-party action causes harm, lack of an "
            "outbound audit trail makes attribution difficult.",
            "Log every outbound call with subject, target, and the "
            "request id, including the vendor's response id.",
            Severity.LOW,
        )],
        StrideCategory.INFORMATION_DISCLOSURE: [(
            "unmasked_pii_to_vendor",
            "PII shared with the third party beyond what's required",
            "Convenience-driven integrations frequently send more "
            "fields to a vendor than the function requires.",
            "Field-by-field allow-list for outbound payloads; data-"
            "minimisation review at integration.",
            Severity.HIGH,
        )],
        StrideCategory.DENIAL_OF_SERVICE: [(
            "vendor_hard_dependency",
            "Hard runtime dependency on a third-party with no fallback",
            "A vendor outage takes our system down with it.",
            "Circuit-break around vendor calls; cache last-good "
            "response; degrade gracefully.",
            Severity.MEDIUM,
        )],
        StrideCategory.ELEVATION_OF_PRIVILEGE: [(
            "vendor_token_overscoped",
            "Vendor API token granted broader scopes than required",
            "If the vendor token is compromised, the blast radius is "
            "the entire scope set.",
            "Minimum-scope tokens per integration; rotate on a "
            "schedule; alert on scope-add.",
            Severity.MEDIUM,
        )],
    },
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def threats_for(component: Component) -> list[Threat]:
    """Return all rule-derived threats for a single component."""
    rules_for_type = _CATALOGUE.get(component.type, {})
    delta = _sensitivity_delta(component.sensitivity)
    out: list[Threat] = []
    for category, rules in rules_for_type.items():
        for slug, title, description, recommendation, base_sev in rules:
            sev = _shift_severity(base_sev, delta)
            stride_letter = _CATEGORY_LETTER[category]
            out.append(Threat(
                threat_id=f"{component.type.value}.{stride_letter}.{slug}",
                component=component.name,
                component_type=component.type.value,
                stride_category=category,
                title=title,
                description=description,
                recommendation=recommendation,
                severity=sev,
                source="rules",
                references=[
                    "Shostack 2014, Threat Modeling: Designing for "
                    "Security (Wiley)",
                ],
            ))
    return out


_CATEGORY_LETTER: dict[StrideCategory, str] = {
    StrideCategory.SPOOFING:               "S",
    StrideCategory.TAMPERING:              "T",
    StrideCategory.REPUDIATION:            "R",
    StrideCategory.INFORMATION_DISCLOSURE: "I",
    StrideCategory.DENIAL_OF_SERVICE:      "D",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "E",
}


def catalogue_size() -> int:
    """Total number of distinct rule entries (component_type x category x slug)."""
    n = 0
    for cat_map in _CATALOGUE.values():
        for rules in cat_map.values():
            n += len(rules)
    return n
