# Spec: Controlled Recovery Validation

## Objective
Build a contained recovery-validation utility for Diaz, Hart, and Reyes. It copies eligible staging data into an isolated exercise, encrypts each copy with AES-256-GCM, decrypts it into a restoration area, verifies exact SHA-256 equality, measures recovery time, and emits auditor-ready JSON evidence.

## Assumptions
1. The input is authorized staging data, never a live clinical-data tree.
2. Only regular `.docx` and `.pdf` files are eligible; symbolic links and special files are rejected.
3. The source, output, and key paths are distinct, resolved paths.
4. A four-hour RTO is the pass threshold; RPO is zero bytes because restored content must exactly match source content.
5. Audit forwarding is optional, HTTPS-only, and configured by the operator. No endpoint is embedded. The receiver must acknowledge `accepted: true` and echo the correlation ID.
6. The systemd unit is delivered as an installable template but is not installed or enabled by this build.

## Tech Stack
- Python 3.11+
- `cryptography` with AES-256-GCM
- TOML configuration through `tomllib`
- `pytest`, `ruff`, and `mypy`
- systemd `Type=oneshot`

## Commands
- Install: `python -m pip install -e '.[dev]'`
- Test: `python -m pytest`
- Lint: `python -m ruff check .`
- Type check: `python -m mypy src`
- Exercise: `recovery-validation run --config ./config.example.toml`

## Project Structure
- `src/recovery_validation/`: validation engine, configuration, audit forwarding, and CLI
- `tests/`: unit and end-to-end recovery tests
- `systemd/`: hardened unit template
- `docs/`: specification, threat model, and operator runbook
- `tasks/`: implementation plan and completion ledger

## Code Style
Typed Python. Small modules. Explicit domain exceptions. Atomic writes for evidence. No logging of source paths, plaintext, or key bytes.

```python
def sha256_file(path: Path, buffer_size: int = 65_536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(buffer_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
```

## Testing Strategy
- Unit tests cover configuration and boundary rejection.
- Integration tests exercise encrypt, decrypt, authentication failure, and exact restoration.
- End-to-end tests verify reports, RTO/RPO fields, and optional HTTPS-forwarding behavior through a fake transport.
- Tests use only temporary directories and synthetic documents.

## Boundaries
- Always: fail closed, use fresh 256-bit keys and 96-bit nonces, authenticate metadata, verify restored SHA-256 digests, fsync evidence, use restrictive modes.
- Ask first: install/enable the service, connect to a real audit endpoint, change eligible file types.
- Never: modify source data, follow symlinks, recurse into the output tree, expose keys in logs/reports, accept HTTP audit endpoints.

## Success Criteria
- Every eligible staged file produces one authenticated ciphertext and one byte-identical restored copy.
- Any tag, ciphertext, metadata, or key corruption fails the exercise.
- Summary and compliance reports contain per-file verification, durations, aggregate RTO/RPO results, signer fields for Diaz and Hart, and a correlation ID.
- The tool exits non-zero on any validation failure.
- The full test, lint, and type-check suites pass.

## Open Questions
- The production audit endpoint, CA bundle, and bearer-token environment-variable name remain deployment inputs.
- Service installation and enablement require Diaz's operational approval.
