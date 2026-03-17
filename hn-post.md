# Show HN Post Draft

**Title:** Show HN: VOAF – Open standard for cryptographically verifiable AI audit trails

**URL:** https://github.com/dip-vigilsec/voaf-spec

**Text:**

Hi HN,

We built Vigil, a local-first AI security proxy that sits between your apps and AI providers (OpenAI, Anthropic, etc.) to intercept, analyze, and audit every interaction. While building it, we realized there's no standard format for AI audit logs — every tool rolls its own, making it impossible to share data across security tools or prove an audit trail hasn't been tampered with.

So we're open-sourcing VOAF (Vigil Open Audit Format), a minimal JSON schema for AI interaction audit trails with a few key properties:

- **SHA-256 hash chain** — each entry hashes the previous one, forming a tamper-evident append-only chain (like a mini blockchain, minus the blockchain)
- **8 required fields** — timestamp, provider, model, direction, content hash, previous hash. Everything else is optional
- **Gate decisions are first-class** — ALLOW, BLOCK, and FLAG are part of the schema, not metadata. Blocked requests stay in the chain so you have a complete record of what was stopped and why
- **Privacy-preserving** — store `content_hash` without the raw content. Prove what happened without exposing what was said
- **Provider-agnostic** — works with any HTTP-based AI API

We've been using this internally in Vigil's Rust proxy for months. The hash chain has caught two accidental log mutations during development that would have gone unnoticed with plain log files.

The schema is formally specified as JSON Schema 2020-12, with examples and validation instructions in the repo.

We think any AI gateway, proxy, or agent framework could benefit from a shared audit format — especially as AI compliance requirements start appearing. Happy to hear feedback on the schema design.

GitHub: https://github.com/dip-vigilsec/voaf-spec
Landing page: https://vigilsec.ai/voaf
Schema: https://github.com/dip-vigilsec/voaf-spec/blob/main/schema/voaf-v1.0.schema.json
