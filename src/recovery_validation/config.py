from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from recovery_validation.errors import ConfigurationError

DEFAULT_RTO_SECONDS = 4 * 60 * 60
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExerciseConfig:
    source_dir: Path
    output_dir: Path
    rto_seconds: float = DEFAULT_RTO_SECONDS
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    audit_endpoint: str | None = None
    audit_token_env: str | None = None
    ca_bundle: Path | None = None
    request_timeout_seconds: float = 10.0

    def validate_values(self) -> None:
        if self.rto_seconds <= 0:
            raise ConfigurationError("rto_seconds must be greater than zero")
        if self.max_file_bytes <= 0:
            raise ConfigurationError("max_file_bytes must be greater than zero")
        if self.request_timeout_seconds <= 0 or self.request_timeout_seconds > 60:
            raise ConfigurationError("request_timeout_seconds must be between 0 and 60")
        if bool(self.audit_endpoint) != bool(self.audit_token_env):
            raise ConfigurationError(
                "audit_endpoint and audit_token_env must be configured together"
            )
        if self.ca_bundle is not None and not self.ca_bundle.is_file():
            raise ConfigurationError("ca_bundle must identify a readable file")


def load_config(path: Path) -> ExerciseConfig:
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("Configuration path must be a regular TOML file")
    try:
        with path.open("rb") as stream:
            document: Any = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"Unable to read configuration: {error}") from error
    if not isinstance(document, dict):
        raise ConfigurationError("Configuration root must be a TOML table")

    allowed = {
        "source_dir",
        "output_dir",
        "rto_seconds",
        "max_file_bytes",
        "audit_endpoint",
        "audit_token_env",
        "ca_bundle",
        "request_timeout_seconds",
    }
    unknown = set(document) - allowed
    if unknown:
        raise ConfigurationError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    source_dir = _required_string(document, "source_dir")
    output_dir = _required_string(document, "output_dir")

    try:
        config = ExerciseConfig(
            source_dir=Path(source_dir),
            output_dir=Path(output_dir),
            rto_seconds=float(document.get("rto_seconds", DEFAULT_RTO_SECONDS)),
            max_file_bytes=int(document.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)),
            audit_endpoint=_optional_string(document, "audit_endpoint"),
            audit_token_env=_optional_string(document, "audit_token_env"),
            ca_bundle=(
                Path(value)
                if (value := _optional_string(document, "ca_bundle")) is not None
                else None
            ),
            request_timeout_seconds=float(document.get("request_timeout_seconds", 10.0)),
        )
    except (TypeError, ValueError) as error:
        raise ConfigurationError("Configuration contains an invalid numeric value") from error
    config.validate_values()
    return config


def _required_string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{key} must be a non-empty string")
    return value


def _optional_string(document: dict[str, Any], key: str) -> str | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{key} must be a non-empty string when configured")
    return value
