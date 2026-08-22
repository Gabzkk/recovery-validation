# Recovery Validation Tasks

- [x] Task 1: Cryptographic core
  - Acceptance: AES-256-GCM round trip succeeds; tampering fails; key mode is `0600`.
  - Verify: `python -m pytest tests/test_crypto.py`
  - Files: `tests/test_crypto.py`, `src/recovery_validation/crypto.py`, `src/recovery_validation/errors.py`

- [x] Task 2: Contained exercise engine
  - Acceptance: only staged regular `.docx`/`.pdf` files are processed; sources are unchanged; reports prove exact restoration.
  - Verify: `python -m pytest tests/test_engine.py`
  - Files: `tests/test_engine.py`, `src/recovery_validation/config.py`, `src/recovery_validation/engine.py`, `src/recovery_validation/reporting.py`

- [x] Task 3: Operator surface
  - Acceptance: CLI validates configuration; systemd unit is hardened; forwarding is opt-in and HTTPS-only.
  - Verify: `python -m pytest tests/test_cli.py tests/test_forwarder.py`
  - Files: `src/recovery_validation/cli.py`, `src/recovery_validation/forwarder.py`, `systemd/recovery-validation.service`, `config.example.toml`

- [x] Task 4: Release verification
  - Acceptance: tests, lint, typing, dependency audit, and synthetic live exercise pass; documentation is complete.
  - Verify: `python -m pytest && python -m ruff check . && python -m mypy src`
  - Files: `README.md`, `docs/threat-model.md`, `docs/runbook.md`
