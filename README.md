# VOAF — Vigil Open Audit Format

**Version 2.0.0** | [Preimage spec](spec/2.0/preimage.md) | [Test vectors](spec/2.0/test-vectors.json) | [Changelog](CHANGELOG.md)

> **2.0 covers message content. 1.0 did not.**
> The 1.0 preimage hashed `prev_hash || id || timestamp || features_json`, so a
> 1.0 chain proves a record existed in an order, not what it said. A 2.x verifier
> reads a 1.0 document in link-only mode and says so rather than reporting it as
> verified. See the [changelog](CHANGELOG.md) for the full account.

VOAF is an open, vendor-neutral JSON format for recording AI interaction audit trails. It provides a cryptographically verifiable, append-only log of every request and response between humans and AI systems — including metadata for policy decisions, anomaly flags, and blocked interactions.

## Why VOAF?

Organizations adopting AI lack a standard way to:

- **Audit** what was sent to and received from AI models
- **Prove** the audit trail has not been tampered with (hash chain integrity)
- **Enforce** that policy violations were caught and acted upon
- **Share** audit data across tools without vendor lock-in

VOAF solves this with a minimal, well-defined JSON schema that any proxy, gateway, or agent framework can emit and any SIEM, compliance tool, or dashboard can consume.

## Key Properties

| Property | Description |
|---|---|
| **Append-only hash chain** | Each entry includes a SHA-256 hash of the previous entry, forming a tamper-evident chain |
| **Provider-agnostic** | Works with OpenAI, Anthropic, Google, Cohere, open-source models, or any HTTP-based AI API |
| **Gate decisions included** | `ALLOW`, `BLOCK`, and `FLAG` decisions are first-class fields, not afterthoughts |
| **Minimal required fields** | Only 8 required fields per entry — everything else is optional extensions |
| **Streaming-friendly** | Entries can be written as each interaction completes; no need to buffer an entire session |

## Quick Start

A minimal VOAF entry:

```json
{
  "voaf": "1.0.0",
  "id": "evt_01J7K9X2M3N4P5Q6R7S8T9U0V1",
  "timestamp": "2026-03-17T12:00:00.000Z",
  "provider": "openai",
  "model": "gpt-4o",
  "direction": "request",
  "content_hash": "sha256:a1b2c3d4e5f6...",
  "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "gate_decision": "ALLOW"
}
```

See [examples/basic.voaf.json](examples/basic.voaf.json) for a full request-response pair with hash chain linkage.

## Schema

The canonical JSON Schema is at [`schema/voaf-v1.0.schema.json`](schema/voaf-v1.0.schema.json).

Validate a VOAF file:

```bash
# Using ajv-cli
npx ajv validate -s schema/voaf-v1.0.schema.json -d your-audit.voaf.json

# Using check-jsonschema
check-jsonschema --schemafile schema/voaf-v1.0.schema.json your-audit.voaf.json
```

## Entry Fields

### Required

| Field | Type | Description |
|---|---|---|
| `voaf` | string | Schema version (`"1.0.0"`) |
| `id` | string | Unique event identifier |
| `timestamp` | string (ISO 8601) | When the event was recorded |
| `provider` | string | AI provider identifier (e.g. `"openai"`, `"anthropic"`) |
| `model` | string | Model identifier (e.g. `"gpt-4o"`, `"claude-sonnet-4-20250514"`) |
| `direction` | enum | `"request"` or `"response"` |
| `content_hash` | string | `sha256:` prefixed hash of the raw content body |
| `prev_hash` | string | `sha256:` hash of the previous entry (genesis entry uses all zeros) |

### Gate Decision (recommended)

| Field | Type | Description |
|---|---|---|
| `gate_decision` | enum | `"ALLOW"`, `"BLOCK"`, or `"FLAG"` |
| `gate_reason` | string | Human-readable reason (required when `BLOCK` or `FLAG`) |
| `gate_policy_id` | string | Identifier of the policy that triggered the decision |
| `gate_layer` | integer | Which detection layer triggered (1 = signatures, 2 = policy, 3 = anomaly) |

### Optional Metadata

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Groups related interactions into a session |
| `user_id` | string | Pseudonymous user identifier |
| `device_id` | string | Originating device identifier |
| `content_body` | string | Raw content (omit for privacy; `content_hash` is sufficient for verification) |
| `token_count` | object | `{ "input": int, "output": int }` |
| `latency_ms` | integer | Round-trip latency in milliseconds |
| `tags` | array[string] | Freeform tags for categorization |
| `annotations` | object | Arbitrary key-value metadata |
| `decomposition` | object | Semantic decomposition output (see schema for structure) |

## Hash Chain Verification

The chain is verified by recomputing each entry's expected `prev_hash`:

```
entry[0].prev_hash == sha256:0000...0000  (genesis)
entry[n].prev_hash == SHA-256(canonical_json(entry[n-1]))
```

Canonical JSON is produced by serializing with sorted keys and no whitespace. Any broken link indicates tampering.

## File Conventions

| Convention | Value |
|---|---|
| File extension | `.voaf.json` |
| MIME type | `application/vnd.voaf+json` |
| Encoding | UTF-8 |
| Top-level structure | JSON array of entry objects |
| Line-delimited variant | `.voaf.jsonl` (one entry per line) |

## Implementations

| Project | Language | Description |
|---|---|---|
| [Vigil](https://github.com/dip-vigilsec/vigil) | Rust | Reference implementation — local AI security proxy with native VOAF export |

Want to add your implementation? Open a PR.

## Contributing

We welcome contributions. Please see the [schema](schema/voaf-v1.0.schema.json) for the normative specification. Open an issue for proposed changes to required fields or hash chain semantics.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

VOAF is maintained by [Vigil Security](https://vigilsec.ai) and the open-source community.
