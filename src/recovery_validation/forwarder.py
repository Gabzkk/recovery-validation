from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from recovery_validation.errors import AuditForwardError, ConfigurationError

MAX_RESPONSE_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class ForwardResponse:
    status: int
    body: bytes


@dataclass(frozen=True, slots=True)
class ForwardReceipt:
    status: int
    accepted: bool


Transport = Callable[[str, bytes, dict[str, str], float], ForwardResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class AuditForwarder:
    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        ca_bundle: Path | None = None,
        timeout_seconds: float = 10.0,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError("Audit endpoint must be an absolute HTTPS URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ConfigurationError("Audit endpoint must not contain credentials or a fragment")
        if not token or "\r" in token or "\n" in token:
            raise ConfigurationError("Audit bearer token is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ConfigurationError("Audit timeout must be between 0 and 60 seconds")
        self.endpoint = endpoint
        self.token = token
        self.timeout_seconds = timeout_seconds
        self._transport = transport or self._build_transport(ca_bundle)

    def forward(self, report_path: Path, *, correlation_id: str) -> ForwardReceipt:
        try:
            body = report_path.read_bytes()
            document = json.loads(body)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConfigurationError("Audit report must be readable valid JSON") from error
        if not isinstance(document, dict):
            raise ConfigurationError("Audit report JSON root must be an object")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Correlation-ID": correlation_id,
        }
        try:
            response = self._transport(self.endpoint, body, headers, self.timeout_seconds)
        except (OSError, urllib.error.URLError) as error:
            raise AuditForwardError("Audit endpoint request failed") from error
        if not 200 <= response.status < 300:
            raise AuditForwardError(f"Audit endpoint returned HTTP {response.status}")
        try:
            acknowledgement = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditForwardError("Audit endpoint acknowledgement is not valid JSON") from error
        if (
            not isinstance(acknowledgement, dict)
            or acknowledgement.get("accepted") is not True
            or acknowledgement.get("correlation_id") != correlation_id
        ):
            raise AuditForwardError("Audit endpoint acknowledgement did not verify delivery")
        return ForwardReceipt(status=response.status, accepted=True)

    @staticmethod
    def _build_transport(ca_bundle: Path | None) -> Transport:
        context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

        def send(url: str, body: bytes, headers: dict[str, str], timeout: float) -> ForwardResponse:
            request = urllib.request.Request(  # noqa: S310 - constructor receives validated HTTPS URL
                url,
                data=body,
                headers=headers,
                method="POST",
            )
            with opener.open(request, timeout=timeout) as response:
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(response_body) > MAX_RESPONSE_BYTES:
                    raise AuditForwardError("Audit endpoint response exceeded 65536 bytes")
                return ForwardResponse(status=response.status, body=response_body)

        return send
