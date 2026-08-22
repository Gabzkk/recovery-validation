from __future__ import annotations

import json
from pathlib import Path

from recovery_validation.cli import main


def test_cli_runs_exercise_from_toml(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "staging"
    source.mkdir()
    (source / ".recovery-validation-staging").write_text("authorized\n", encoding="utf-8")
    (source / "sample.pdf").write_bytes(b"%PDF synthetic")
    output = tmp_path / "output"
    config = tmp_path / "config.toml"
    config.write_text(
        f'source_dir = "{source}"\noutput_dir = "{output}"\nrto_seconds = 14400\n',
        encoding="utf-8",
    )

    assert main(["run", "--config", str(config)]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    result = json.loads(captured.out)
    assert result["status"] == "PASS"
    assert result["files_verified"] == 1


def test_cli_returns_nonzero_for_invalid_config(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "config.toml"
    config.write_text('source_dir = "/missing"\noutput_dir = "/also-missing"\n', encoding="utf-8")

    assert main(["run", "--config", str(config)]) == 2
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    error = json.loads(captured.err)
    assert error["status"] == "ERROR"
    assert error["error_type"] == "ConfigurationError"
