from __future__ import annotations

import json
from pathlib import Path

import pytest

from recovery_validation.errors import AuditForwardError, ConfigurationError
from recovery_validation.forwarder import AuditForwarder, ForwardResponse


def test_forwarder_requires_https() -> None:
    with pytest.raises(ConfigurationError, match="HTTPS"):
        AuditForwarder(endpoint="http://audit.example.test/reports", token="secret")


def test_forwarder_sends_json_with_authentication(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"status":"PASS"}\n', encoding="utf-8")
    captured: dict[str, object] = {}

    def transport(
        url: str, body: bytes, headers: dict[str, str], timeout: float
    ) -> ForwardResponse:
        captured.update(url=url, body=body, headers=headers, timeout=timeout)
        return ForwardResponse(
            status=202,
            body=b'{"accepted":true,"correlation_id":"exercise-005"}',
        )

    forwarder = AuditForwarder(
        endpoint="https://audit.example.test/v1/recovery-reports",
        token="secret",
        transport=transport,
    )
    receipt = forwarder.forward(report_path, correlation_id="exercise-005")

    assert captured["url"] == "https://audit.example.test/v1/recovery-reports"
    assert captured["headers"] == {
        "Authorization": "Bearer secret",
        "Content-Type": "application/json",
        "X-Correlation-ID": "exercise-005",
    }
    assert json.loads(captured["body"]) == {"status": "PASS"}
    assert receipt.status == 202


def test_forwarder_rejects_non_json_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("not-json", encoding="utf-8")
    forwarder = AuditForwarder(endpoint="https://audit.example.test/reports", token="secret")

    with pytest.raises(ConfigurationError, match="valid JSON"):
        forwarder.forward(report_path, correlation_id="exercise-006")


def test_forwarder_rejects_unverified_receiver_acknowledgement(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"status":"PASS"}\n', encoding="utf-8")

    def transport(
        url: str, body: bytes, headers: dict[str, str], timeout: float
    ) -> ForwardResponse:
        return ForwardResponse(status=202, body=b'{"accepted":false}')

    forwarder = AuditForwarder(
        endpoint="https://audit.example.test/reports",
        token="test-token",
        transport=transport,
    )

    with pytest.raises(AuditForwardError, match="acknowledgement"):
        forwarder.forward(report_path, correlation_id="exercise-007")
