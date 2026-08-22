from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from recovery_validation.config import ExerciseConfig
from recovery_validation.engine import run_exercise
from recovery_validation.errors import ConfigurationError, ContainmentError
from recovery_validation.forwarder import ForwardReceipt


def staged_source(tmp_path: Path) -> Path:
    source = tmp_path / "staging"
    source.mkdir()
    (source / ".recovery-validation-staging").write_text("authorized\n", encoding="utf-8")
    return source


def test_exercise_restores_docx_and_pdf_and_preserves_sources(tmp_path: Path) -> None:
    source = staged_source(tmp_path)
    nested = source / "case-set"
    nested.mkdir()
    pdf = source / "record.pdf"
    docx = nested / "record.docx"
    ignored = source / "notes.txt"
    pdf.write_bytes(b"%PDF-1.7 synthetic\n" + os.urandom(4096))
    docx.write_bytes(b"PK synthetic docx\n" + os.urandom(2048))
    ignored.write_text("not eligible", encoding="utf-8")
    before = {path: path.read_bytes() for path in (pdf, docx, ignored)}

    report = run_exercise(ExerciseConfig(source_dir=source, output_dir=tmp_path / "output"))

    assert report.status == "PASS"
    assert report.rto.status == "PASS"
    assert report.rpo.bytes_lost == 0
    assert report.files_discovered == 2
    assert report.files_verified == 2
    assert all(item.decryption_verified for item in report.files)
    assert all(item.source_unchanged for item in report.files)
    assert {path: path.read_bytes() for path in (pdf, docx, ignored)} == before
    assert not (tmp_path / "output" / "latest" / "restored" / "notes.txt").exists()

    report_path = tmp_path / "output" / report.correlation_id / "compliance-report.json"
    summary_path = tmp_path / "output" / report.correlation_id / "validation-summary.json"
    audit_path = tmp_path / "output" / report.correlation_id / "audit.jsonl"
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == "PASS"
    assert json.loads(summary_path.read_text(encoding="utf-8"))["files_verified"] == 2
    audit_entries = audit_path.read_text(encoding="utf-8").splitlines()
    assert all(
        json.loads(line)["correlation_id"] == report.correlation_id for line in audit_entries
    )


def test_source_requires_explicit_staging_marker(tmp_path: Path) -> None:
    source = tmp_path / "unmarked"
    source.mkdir()
    (source / "record.pdf").write_bytes(b"synthetic")

    with pytest.raises(ContainmentError, match="staging marker"):
        run_exercise(ExerciseConfig(source_dir=source, output_dir=tmp_path / "output"))


def test_source_and_output_overlap_is_rejected(tmp_path: Path) -> None:
    source = staged_source(tmp_path)

    with pytest.raises(ContainmentError, match="must not overlap"):
        run_exercise(ExerciseConfig(source_dir=source, output_dir=source / "output"))


def test_symlink_in_staging_tree_is_rejected(tmp_path: Path) -> None:
    source = staged_source(tmp_path)
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"outside")
    (source / "linked.pdf").symlink_to(outside)

    with pytest.raises(ContainmentError, match="symbolic link"):
        run_exercise(ExerciseConfig(source_dir=source, output_dir=tmp_path / "output"))


def test_empty_eligible_dataset_fails(tmp_path: Path) -> None:
    source = staged_source(tmp_path)
    (source / "notes.txt").write_text("not eligible", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="No eligible"):
        run_exercise(ExerciseConfig(source_dir=source, output_dir=tmp_path / "output"))


def test_configured_audit_summary_is_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = staged_source(tmp_path)
    (source / "record.pdf").write_bytes(b"synthetic")
    observed: dict[str, object] = {}

    class FakeForwarder:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

        def forward(self, report_path: Path, *, correlation_id: str) -> ForwardReceipt:
            observed.update(report_path=report_path, correlation_id=correlation_id)
            return ForwardReceipt(status=202, accepted=True)

    monkeypatch.setenv("RECOVERY_AUDIT_TOKEN", "secret")
    monkeypatch.setattr("recovery_validation.engine.AuditForwarder", FakeForwarder)
    report = run_exercise(
        ExerciseConfig(
            source_dir=source,
            output_dir=tmp_path / "output",
            audit_endpoint="https://audit.example.test/recovery",
            audit_token_env="RECOVERY_AUDIT_TOKEN",
        )
    )

    assert observed["endpoint"] == "https://audit.example.test/recovery"
    assert observed["token"] == "secret"
    assert Path(observed["report_path"]).name == "validation-summary.json"  # type: ignore[arg-type]
    assert report.audit_forwarding == {"status": "DELIVERED", "http_status": 202}
