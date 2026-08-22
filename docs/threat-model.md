# Threat Model

## Assets
- Authorized staging copies of healthcare documents.
- Per-exercise AES-256-GCM keys.
- Ciphertexts, restored copies, and audit evidence.
- Audit bearer token and TLS trust store.

## Trust Boundaries
1. Operator TOML enters the process as untrusted configuration.
2. The staging tree enters as untrusted filesystem state.
3. Encrypted containers enter the decryptor as untrusted binary input.
4. The audit receiver is an external HTTPS boundary.

## STRIDE Controls
| Threat | Control |
|---|---|
| Spoofed staging source | Required marker, canonical path checks, service read-only path |
| Tampered ciphertext or metadata | AES-256-GCM authentication with metadata as associated data |
| Repudiated exercise result | Correlation ID and fsynced JSONL audit events |
| Information disclosure | No filenames, plaintext, keys, tokens, or full URLs in reports/logs |
| Resource exhaustion | Eligible-type allowlist, per-file size cap, bounded buffers and HTTP response |
| Privilege escalation | Dedicated user, empty capability set, `NoNewPrivileges`, systemd sandboxing |

## Abuse Cases
- A source path inside the output path, or the reverse, is rejected.
- Any symbolic link in the staging tree is rejected.
- Missing staging authorization marker is rejected.
- Unsupported files are ignored; oversized eligible files stop the run.
- A wrong key or altered ciphertext, tag, nonce, or header leaves no restored output.
- HTTP, credential-bearing URLs, redirects, oversized responses, and invalid receiver acknowledgements are rejected.

## Residual Risk
- The exercise key is stored on the same host as its artifacts. Production deployment should replace local key files with approved key escrow or a KMS-backed envelope-encryption design.
- Filenames exist in the isolated encrypted/restored directory structure even though reports redact them. Access to the run directory must remain restricted.
