from __future__ import annotations

import os
from pathlib import Path

import pytest

from recovery_validation.crypto import (
    KEY_BYTES,
    decrypt_file,
    encrypt_file,
    generate_key_file,
    sha256_file,
)
from recovery_validation.errors import DecryptionError, IntegrityError


def test_aes_256_gcm_round_trip_restores_exact_bytes(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    encrypted = tmp_path / "sealed" / "input.rvg"
    restored = tmp_path / "restored" / "input.pdf"
    key_path = tmp_path / "keys" / "exercise.key"
    source.write_bytes(os.urandom(131_071))

    key = generate_key_file(key_path)
    metadata = encrypt_file(
        source,
        encrypted,
        key,
        correlation_id="exercise-001",
        file_id="file-001",
    )
    result = decrypt_file(encrypted, restored, key)

    assert len(key) == KEY_BYTES
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert restored.read_bytes() == source.read_bytes()
    assert result.sha256 == sha256_file(source) == metadata.sha256
    assert result.size_bytes == source.stat().st_size


def test_modified_ciphertext_fails_without_plaintext_output(tmp_path: Path) -> None:
    source = tmp_path / "input.docx"
    encrypted = tmp_path / "input.rvg"
    restored = tmp_path / "restored.docx"
    key = os.urandom(KEY_BYTES)
    source.write_bytes(b"synthetic document content")
    encrypt_file(source, encrypted, key, correlation_id="exercise-002", file_id="file-002")

    payload = bytearray(encrypted.read_bytes())
    payload[-17] ^= 0x01
    encrypted.write_bytes(payload)

    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt_file(encrypted, restored, key)
    assert not restored.exists()


def test_wrong_key_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    encrypted = tmp_path / "input.rvg"
    restored = tmp_path / "restored.pdf"
    source.write_bytes(b"synthetic pdf")
    encrypt_file(
        source,
        encrypted,
        os.urandom(KEY_BYTES),
        correlation_id="exercise-003",
        file_id="file-003",
    )

    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt_file(encrypted, restored, os.urandom(KEY_BYTES))
    assert not restored.exists()


def test_invalid_key_length_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "input.pdf"
    source.write_bytes(b"synthetic pdf")

    with pytest.raises(IntegrityError, match="32 bytes"):
        encrypt_file(
            source,
            tmp_path / "output.rvg",
            b"short",
            correlation_id="exercise-004",
            file_id="file-004",
        )
