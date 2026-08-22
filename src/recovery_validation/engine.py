from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from recovery_validation.config import ExerciseConfig
from recovery_validation.crypto import (
    decrypt_file,
    encrypt_file,
    generate_key_file,
    sha256_file,
)
from recovery_validation.errors import AuditForwardError, ConfigurationError, ContainmentError
from recovery_validation.forwarder import AuditForwarder
from recovery_validation.reporting import (
    AuditLog,
    ComplianceReport,
    FileResult,
    RpoResult,
    RtoResult,
    utc_now,
    write_json_atomic,
)

ELIGIBLE_SUFFIXES = frozenset({".docx", ".pdf"})
STAGING_MARKER = ".recovery-validation-staging"


def run_exercise(config: ExerciseConfig) -> ComplianceReport:
    config.validate_values()
    audit_token = _load_audit_token(config)
    source_root, output_root = _validate_boundaries(config)
    eligible_files = _discover_files(source_root, config.max_file_bytes)
    if not eligible_files:
        raise ConfigurationError("No eligible .docx or .pdf files were found")

    correlation_id = str(uuid.uuid4())
    run_root = output_root / correlation_id
    encrypted_root = run_root / "encrypted"
    restored_root = run_root / "restored"
    key_path = run_root / "keys" / "exercise.key"
    run_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    audit = AuditLog(run_root / "audit.jsonl", correlation_id)
    key = generate_key_file(key_path)
    started_at = utc_now()
    start_time = time.monotonic()
    audit.record(
        "recovery_exercise_started",
        eligible_files=len(eligible_files),
        rto_threshold_seconds=config.rto_seconds,
    )

    results: list[FileResult] = []
    for source in eligible_files:
        relative = source.relative_to(source_root)
        file_id = hmac.new(key, relative.as_posix().encode("utf-8"), hashlib.sha256).hexdigest()
        encrypted = encrypted_root / relative.parent / f"{relative.name}.rvg"
        restored = restored_root / relative
        source_digest_before = sha256_file(source)
        source_size = source.stat().st_size
        encryption_started = time.monotonic()
        try:
            encrypt_file(
                source,
                encrypted,
                key,
                correlation_id=correlation_id,
                file_id=file_id,
            )
            encryption_seconds = time.monotonic() - encryption_started
            decryption_started = time.monotonic()
            metadata = decrypt_file(encrypted, restored, key)
            decryption_seconds = time.monotonic() - decryption_started
            restored_digest = sha256_file(restored)
            source_digest_after = sha256_file(source)
            verified = (
                restored_digest == source_digest_before == metadata.sha256
                and restored.stat().st_size == source_size == metadata.size_bytes
            )
            source_unchanged = source_digest_after == source_digest_before
            status = "PASS" if verified and source_unchanged else "FAIL"
            result = FileResult(
                file_id=file_id,
                size_bytes=source_size,
                sha256_original=source_digest_before,
                sha256_restored=restored_digest,
                encryption_seconds=round(encryption_seconds, 6),
                decryption_seconds=round(decryption_seconds, 6),
                decryption_verified=verified,
                source_unchanged=source_unchanged,
                status=status,
                error_type=None if status == "PASS" else "IntegrityError",
            )
        except Exception as error:
            result = FileResult(
                file_id=file_id,
                size_bytes=source_size,
                sha256_original=source_digest_before,
                sha256_restored=None,
                encryption_seconds=round(time.monotonic() - encryption_started, 6),
                decryption_seconds=0.0,
                decryption_verified=False,
                source_unchanged=sha256_file(source) == source_digest_before,
                status="FAIL",
                error_type=type(error).__name__,
            )
        results.append(result)
        audit.record(
            "recovery_file_verified" if result.status == "PASS" else "recovery_file_failed",
            level="info" if result.status == "PASS" else "error",
            file_id=file_id,
            size_bytes=source_size,
            status=result.status,
            error_type=result.error_type,
            encryption_seconds=result.encryption_seconds,
            decryption_seconds=result.decryption_seconds,
        )

    measured_seconds = time.monotonic() - start_time
    verified_results = [item for item in results if item.status == "PASS"]
    bytes_lost = sum(item.size_bytes for item in results if item.status != "PASS")
    rto_status = "PASS" if measured_seconds <= config.rto_seconds else "FAIL"
    rpo_status = "PASS" if bytes_lost == 0 else "FAIL"
    recovery_status = (
        "PASS"
        if len(verified_results) == len(results) and rto_status == "PASS" and rpo_status == "PASS"
        else "FAIL"
    )
    summary = {
        "schema_version": "1.0",
        "correlation_id": correlation_id,
        "status": recovery_status,
        "algorithm": "AES-256-GCM",
        "files_discovered": len(results),
        "files_verified": len(verified_results),
        "bytes_verified": sum(item.size_bytes for item in verified_results),
        "rto": {
            "threshold_seconds": config.rto_seconds,
            "measured_seconds": round(measured_seconds, 6),
            "status": rto_status,
        },
        "rpo": {"target_bytes_lost": 0, "bytes_lost": bytes_lost, "status": rpo_status},
    }
    summary_path = run_root / "validation-summary.json"
    write_json_atomic(summary_path, summary)
    audit_forwarding: dict[str, object] = {"status": "DISABLED"}
    forwarding_failed = False
    if config.audit_endpoint is not None and audit_token is not None:
        try:
            receipt = AuditForwarder(
                endpoint=config.audit_endpoint,
                token=audit_token,
                ca_bundle=config.ca_bundle,
                timeout_seconds=config.request_timeout_seconds,
            ).forward(summary_path, correlation_id=correlation_id)
            audit_forwarding = {"status": "DELIVERED", "http_status": receipt.status}
            audit.record(
                "audit_summary_forwarded",
                endpoint_host=_endpoint_host(config.audit_endpoint),
                http_status=receipt.status,
            )
        except AuditForwardError as error:
            forwarding_failed = True
            audit_forwarding = {"status": "FAILED", "error_type": type(error).__name__}
            audit.record(
                "audit_summary_forward_failed",
                level="error",
                endpoint_host=_endpoint_host(config.audit_endpoint),
                error_type=type(error).__name__,
            )
    status = "FAIL" if forwarding_failed else recovery_status
    report = ComplianceReport(
        schema_version="1.0",
        correlation_id=correlation_id,
        started_at=started_at,
        completed_at=utc_now(),
        status=status,
        algorithm="AES-256-GCM",
        files_discovered=len(results),
        files_verified=len(verified_results),
        bytes_verified=sum(item.size_bytes for item in verified_results),
        rto=RtoResult(
            threshold_seconds=config.rto_seconds,
            measured_seconds=round(measured_seconds, 6),
            status=rto_status,
        ),
        rpo=RpoResult(target_bytes_lost=0, bytes_lost=bytes_lost, status=rpo_status),
        files=tuple(results),
        audit_forwarding=audit_forwarding,
        personnel={
            "recovery_lead": "Diaz",
            "compliance_officer": "Hart",
            "client_contact": "Reyes",
        },
        signoff={"recovery_lead": "PENDING", "compliance_officer": "PENDING"},
    )
    write_json_atomic(run_root / "compliance-report.json", report.to_dict())
    audit.record(
        "recovery_exercise_completed",
        status=report.status,
        files_verified=report.files_verified,
        measured_seconds=report.rto.measured_seconds,
        rto_status=report.rto.status,
        rpo_status=report.rpo.status,
    )
    return report


def _load_audit_token(config: ExerciseConfig) -> str | None:
    if config.audit_endpoint is None:
        return None
    if config.audit_token_env is None:
        raise ConfigurationError("audit_token_env is required when audit_endpoint is configured")
    token = os.environ.get(config.audit_token_env)
    if not token:
        raise ConfigurationError(
            f"Audit token environment variable {config.audit_token_env} is not set"
        )
    return token


def _endpoint_host(endpoint: str) -> str:
    return urlsplit(endpoint).hostname or "invalid"


def _validate_boundaries(config: ExerciseConfig) -> tuple[Path, Path]:
    try:
        source_root = config.source_dir.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError("source_dir must identify an existing directory") from error
    if not source_root.is_dir():
        raise ConfigurationError("source_dir must identify an existing directory")
    output_root = config.output_dir.resolve(strict=False)
    paths_overlap = (
        source_root == output_root
        or source_root.is_relative_to(output_root)
        or output_root.is_relative_to(source_root)
    )
    if paths_overlap:
        raise ContainmentError("source_dir and output_dir must not overlap")
    marker = source_root / STAGING_MARKER
    if marker.is_symlink() or not marker.is_file():
        raise ContainmentError(f"source_dir must contain the {STAGING_MARKER} staging marker")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return source_root, output_root


def _discover_files(root: Path, max_file_bytes: int) -> list[Path]:
    discovered: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink():
                    raise ContainmentError(f"Staging tree contains a symbolic link: {entry.name}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False) or path.name == STAGING_MARKER:
                    continue
                if path.suffix.lower() not in ELIGIBLE_SUFFIXES:
                    continue
                if entry.stat(follow_symlinks=False).st_size > max_file_bytes:
                    raise ConfigurationError(f"Eligible file exceeds max_file_bytes: {entry.name}")
                discovered.append(path)
    return sorted(discovered, key=lambda path: path.relative_to(root).as_posix())
