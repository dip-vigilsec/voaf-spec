# Changelog

All notable changes to the VOAF specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-17

### Added

- Initial VOAF v1.0.0 specification
- 8 required fields: `voaf`, `id`, `timestamp`, `provider`, `model`, `direction`, `content_hash`, `prev_hash`
- Gate decision fields: `gate_decision`, `gate_reason`, `gate_policy_id`, `gate_layer`
- Optional metadata: `session_id`, `user_id`, `device_id`, `content_body`, `token_count`, `latency_ms`, `tags`, `annotations`
- Semantic decomposition extension object
- SHA-256 append-only hash chain specification
- JSON Schema (`schema/voaf-v1.0.schema.json`)
- Example file with ALLOW, BLOCK, and FLAG entries
- Apache 2.0 license
