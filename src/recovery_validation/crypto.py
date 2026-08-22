from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from recovery_validation.errors import DecryptionError, IntegrityError

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
BUFFER_SIZE = 65_536
MAGIC = b"RVGCM001"
MAX_HEADER_BYTES = 65_536
_HEADER_LENGTH = struct.Struct(">I")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class FileMetadata:
    correlation_id: str
    file_id: str
    sha256: str
    size_bytes: int
    nonce: bytes


def sha256_file(path: Path, buffer_size: int = BUFFER_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(buffer_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_key_file(path: Path) -> bytes:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)
    return key


def load_key_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise IntegrityError("Key path must be a regular file")
    if path.stat().st_mode & 0o077:
        raise IntegrityError("Key file permissions must be 0600 or stricter")
    key = path.read_bytes()
    _validate_key(key)
    return key


def encrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
    *,
    correlation_id: str,
    file_id: str,
) -> FileMetadata:
    _validate_key(key)
    _validate_regular_source(source)
    source_digest = sha256_file(source)
    source_size = source.stat().st_size
    nonce = os.urandom(NONCE_BYTES)
    metadata = FileMetadata(
        correlation_id=correlation_id,
        file_id=file_id,
        sha256=source_digest,
        size_bytes=source_size,
        nonce=nonce,
    )
    header = _encode_header(metadata)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    try:
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header)
        destination_stream = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = -1
        with (
            source.open("rb") as source_stream,
            destination_stream,
        ):
            destination_stream.write(MAGIC)
            destination_stream.write(_HEADER_LENGTH.pack(len(header)))
            destination_stream.write(header)
            for chunk in iter(lambda: source_stream.read(BUFFER_SIZE), b""):
                destination_stream.write(encryptor.update(chunk))
            destination_stream.write(encryptor.finalize())
            destination_stream.write(encryptor.tag)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        _fsync_directory(destination.parent)
    except BaseException:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise

    return metadata


def decrypt_file(source: Path, destination: Path, key: bytes) -> FileMetadata:
    _validate_key(key)
    _validate_regular_source(source)
    total_size = source.stat().st_size

    with source.open("rb") as source_stream:
        metadata, header, ciphertext_size, tag = _read_container_prefix(source_stream, total_size)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        digest = hashlib.sha256()
        bytes_written = 0

        try:
            decryptor = Cipher(algorithms.AES(key), modes.GCM(metadata.nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(header)
            remaining = ciphertext_size
            destination_stream = os.fdopen(descriptor, "wb", closefd=True)
            descriptor = -1
            with destination_stream:
                while remaining:
                    chunk = source_stream.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise DecryptionError(
                            "Encrypted container ended before ciphertext completed"
                        )
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    destination_stream.write(plaintext)
                    digest.update(plaintext)
                    bytes_written += len(plaintext)
                final_plaintext = decryptor.finalize()
                destination_stream.write(final_plaintext)
                digest.update(final_plaintext)
                bytes_written += len(final_plaintext)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
            if bytes_written != metadata.size_bytes:
                raise DecryptionError("Restored size does not match authenticated metadata")
            if digest.hexdigest() != metadata.sha256:
                raise DecryptionError("Restored SHA-256 does not match authenticated metadata")
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            _fsync_directory(destination.parent)
        except InvalidTag as error:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise DecryptionError("AES-256-GCM authentication failed") from error
        except BaseException:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise

    return metadata


def _read_container_prefix(
    stream: BinaryIO, total_size: int
) -> tuple[FileMetadata, bytes, int, bytes]:
    if stream.read(len(MAGIC)) != MAGIC:
        raise DecryptionError("Encrypted container has an invalid magic value")
    raw_length = stream.read(_HEADER_LENGTH.size)
    if len(raw_length) != _HEADER_LENGTH.size:
        raise DecryptionError("Encrypted container has a truncated header length")
    header_length = _HEADER_LENGTH.unpack(raw_length)[0]
    if header_length == 0 or header_length > MAX_HEADER_BYTES:
        raise DecryptionError("Encrypted container header length is invalid")
    header = stream.read(header_length)
    if len(header) != header_length:
        raise DecryptionError("Encrypted container header is truncated")
    metadata = _decode_header(header)
    prefix_size = len(MAGIC) + _HEADER_LENGTH.size + header_length
    ciphertext_size = total_size - prefix_size - TAG_BYTES
    if ciphertext_size < 0:
        raise DecryptionError("Encrypted container is truncated")
    stream.seek(total_size - TAG_BYTES)
    tag = stream.read(TAG_BYTES)
    if len(tag) != TAG_BYTES:
        raise DecryptionError("Encrypted container authentication tag is truncated")
    stream.seek(prefix_size)
    return metadata, header, ciphertext_size, tag


def _encode_header(metadata: FileMetadata) -> bytes:
    document = {
        "algorithm": "AES-256-GCM",
        "correlation_id": metadata.correlation_id,
        "file_id": metadata.file_id,
        "nonce": base64.b64encode(metadata.nonce).decode("ascii"),
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "version": 1,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_header(header: bytes) -> FileMetadata:
    try:
        document: Any = json.loads(header)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DecryptionError("Encrypted container header is not valid JSON") from error
    if not isinstance(document, dict):
        raise DecryptionError("Encrypted container header must be an object")
    expected_keys = {
        "algorithm",
        "correlation_id",
        "file_id",
        "nonce",
        "sha256",
        "size_bytes",
        "version",
    }
    if set(document) != expected_keys:
        raise DecryptionError("Encrypted container header fields are invalid")
    if document["version"] != 1 or document["algorithm"] != "AES-256-GCM":
        raise DecryptionError("Encrypted container format is unsupported")
    if not isinstance(document["correlation_id"], str) or not document["correlation_id"]:
        raise DecryptionError("Encrypted container correlation ID is invalid")
    if not isinstance(document["file_id"], str) or not document["file_id"]:
        raise DecryptionError("Encrypted container file ID is invalid")
    if not isinstance(document["size_bytes"], int) or document["size_bytes"] < 0:
        raise DecryptionError("Encrypted container original size is invalid")
    if not isinstance(document["sha256"], str) or not _SHA256_PATTERN.fullmatch(document["sha256"]):
        raise DecryptionError("Encrypted container SHA-256 is invalid")
    try:
        nonce = base64.b64decode(document["nonce"], validate=True)
    except (TypeError, ValueError) as error:
        raise DecryptionError("Encrypted container nonce is invalid") from error
    if len(nonce) != NONCE_BYTES:
        raise DecryptionError("Encrypted container nonce must be 12 bytes")
    return FileMetadata(
        correlation_id=document["correlation_id"],
        file_id=document["file_id"],
        sha256=document["sha256"],
        size_bytes=document["size_bytes"],
        nonce=nonce,
    )


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise IntegrityError("AES-256-GCM key must be exactly 32 bytes")


def _validate_regular_source(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise IntegrityError("Input path must be a regular file")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
