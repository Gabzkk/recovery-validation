from __future__ import annotations

import contextlib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class FileResult:
    file_id: str
    size_bytes: int
    sha256_original: str
    sha256_restored: str | None
    encryption_seconds: float
    decryption_seconds: float
    decryption_verified: bool
    source_unchanged: bool
    status: str
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class RtoResult:
    threshold_seconds: float
    measured_seconds: float
    status: str


@dataclass(frozen=True, slots=True)
class RpoResult:
    target_bytes_lost: int
    bytes_lost: int
    status: str


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    schema_version: str
    correlation_id: str
    started_at: str
    completed_at: str
    status: str
    algorithm: str
    files_discovered: int
    files_verified: int
    bytes_verified: int
    rto: RtoResult
    rpo: RpoResult
    files: tuple[FileResult, ...]
    audit_forwarding: dict[str, object]
    personnel: dict[str, str]
    signoff: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    def __init__(self, path: Path, correlation_id: str) -> None:
        self.path = path
        self.correlation_id = correlation_id
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def record(self, event: str, *, level: str = "info", **fields: object) -> None:
        entry = {
            "timestamp": utc_now(),
            "level": level,
            "event": event,
            "correlation_id": self.correlation_id,
            **fields,
        }
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(descriptor, "a", encoding="utf-8", closefd=True) as stream:
            stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def write_json_atomic(path: Path, document: dict[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8", closefd=True)
        descriptor = -1
        with stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    except BaseException:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
