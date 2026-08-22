# Recovery Validation Project

## Stack
- Python 3.11+
- `cryptography` AES-256-GCM primitives
- `pytest`, `ruff`, and `mypy` for verification
- systemd unit templates for boot execution

## Commands
- Install: `python -m pip install -e '.[dev]'`
- Test: `python -m pytest`
- Lint: `python -m ruff check .`
- Type check: `python -m mypy src`
- Run: `recovery-validation run --config /etc/recovery-validation/config.toml`

## Conventions
- Keep source datasets immutable.
- Resolve and validate every filesystem boundary before I/O.
- Never log plaintext, key material, patient data, or absolute source paths.
- Use structured JSON for audit records and compliance reports.
- Keep external audit forwarding opt-in and HTTPS-only.

## Boundaries
- Always verify restored bytes against the original SHA-256 digest.
- Always create keys with mode `0600` and reports with mode `0640`.
- Ask before installing or enabling system services.
- Never delete, overwrite, rename, or encrypt source files in place.
- Never commit generated keys, encrypted artifacts, restored datasets, or credentials.
