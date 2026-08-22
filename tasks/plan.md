# Implementation Plan: Controlled Recovery Validation

## Overview
Deliver a fail-closed Python recovery exercise that preserves the source, proves AES-256-GCM decryption, measures RTO/RPO, and writes auditable evidence. External forwarding and boot execution remain operator-controlled.

## Architecture Decisions
- Use one random 256-bit AES key per exercise and one random 96-bit nonce per file.
- Bind format version, correlation ID, file identifier, original size, and original digest as GCM associated data.
- Address files in reports by deterministic relative-path hashes to avoid leaking patient-identifying filenames.
- Use an injectable audit transport so network behavior is testable without external calls.
- Stage systemd configuration without mutating the host.

## Task List

### Phase 1: Contract and Cryptographic Core
- [x] Write failing tests for containment, encryption, authentication failure, and exact restoration.
- [x] Implement configuration, hashing, key custody, and AES-256-GCM container handling.

### Checkpoint: Cryptographic Core
- [x] Focused tests pass.
- [x] No source file changes during an exercise.

### Phase 2: Exercise Orchestration and Evidence
- [x] Write failing end-to-end tests for discovery, RTO/RPO, reports, and exit status.
- [x] Implement orchestration, structured audit events, atomic JSON reports, and optional HTTPS forwarding.

### Checkpoint: Complete Flow
- [x] Synthetic `.docx` and `.pdf` files restore byte-for-byte.
- [x] Corruption produces a non-zero result and clear audit evidence.

### Phase 3: Operations
- [x] Add CLI, example configuration, hardened systemd template, packaging, and runbook.
- [x] Run tests, lint, type checking, dependency audit, and a live synthetic exercise.
- [x] Review correctness, readability, architecture, security, and performance.

### Checkpoint: Complete
- [x] All success criteria pass.
- [x] Service remains uninstalled and forwarding remains disabled by default.

## Risks and Mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Wrong directory selected | High | Resolve paths, reject overlap, require a staging marker |
| Key disclosure | High | Separate key file, mode `0600`, never log key material |
| Partial writes | High | Temporary file, fsync, atomic replace |
| GCM nonce reuse | High | Fresh random nonce per file with duplicate detection |
| Sensitive filenames in reports | Medium | Report keyed HMAC identifiers, not raw paths |
| Audit endpoint abuse | Medium | HTTPS only, fixed configured URL, timeouts, no redirects |

## Open Questions
- Deployment-owned audit endpoint and CA bundle.
- Approval to install and enable the systemd unit.
