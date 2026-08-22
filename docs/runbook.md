# Recovery Validation Runbook

## Preflight
1. Diaz confirms the source is an authorized staging copy, not a live clinical directory.
2. Reyes places only the test `.docx` and `.pdf` files below `/srv/recovery-validation/staging`.
3. Create `/srv/recovery-validation/staging/.recovery-validation-staging` as a regular file.
4. Hart confirms the configured RTO is `14400` seconds and the output volume has enough capacity for ciphertext plus restored copies.
5. If central delivery is approved, put `RECOVERY_AUDIT_TOKEN=...` in `/etc/recovery-validation/audit.env`, owned by root with mode `0600`.

## Manual Exercise
```bash
sudo -u recovery-validation /opt/recovery-validation/venv/bin/recovery-validation \
  run --config /etc/recovery-validation/config.toml
```

Exit codes:
- `0`: recovery, RTO, RPO, and configured forwarding passed.
- `1`: the exercise completed but one or more validation gates failed.
- `2`: configuration, containment, cryptography, or audit transport failed before a complete report.

## Evidence Review
Use the correlation ID printed by the command to open:
- `validation-summary.json`: compact operational verdict.
- `compliance-report.json`: per-file hashes, timings, RTO/RPO, personnel, and signoff state.
- `audit.jsonl`: ordered structured events.
- `keys/exercise.key`: exercise key, mode `0600`; never attach it to the audit report.

Hart verifies every file has `decryption_verified: true` and `source_unchanged: true`. Diaz signs only when the overall status, RTO, and RPO are all `PASS`.

## Failure Handling
1. Do not retry over the same run directory. Every run has a new correlation ID and key.
2. Preserve `audit.jsonl`, the encrypted container, and the failed report for investigation.
3. Compare the event's `error_type` with service logs: `journalctl -u recovery-validation.service --since today`.
4. Correct staging, capacity, permissions, key custody, or endpoint configuration.
5. Run a fresh exercise and cross-reference both correlation IDs in the audit case.

## Service Installation
Installation changes host state and requires Diaz's approval.

```bash
sudo install -Dm0644 systemd/recovery-validation.service /etc/systemd/system/recovery-validation.service
sudo install -Dm0644 systemd/recovery-validation.sysusers /usr/lib/sysusers.d/recovery-validation.conf
sudo install -Dm0644 systemd/recovery-validation.tmpfiles /usr/lib/tmpfiles.d/recovery-validation.conf
sudo systemd-sysusers /usr/lib/sysusers.d/recovery-validation.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/recovery-validation.conf
sudo systemctl daemon-reload
sudo systemctl enable recovery-validation.service
```

Validate before enabling:

```bash
systemd-analyze verify systemd/recovery-validation.service
sudo systemctl start recovery-validation.service
sudo systemctl status recovery-validation.service
```
