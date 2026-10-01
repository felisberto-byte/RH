"""Armazenamento de PDFs (write-once).

Em produção use GCS com *retention policy* (Bucket Lock) para que nem o
próprio sistema consiga apagar/alterar documentos antes do prazo legal.
As gravações são "create-only": regravar uma chave existente é erro.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol


class ObjectExistsError(Exception):
    pass


class Storage(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/pdf") -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...


def _safe_key(key: str) -> str:
    parts = key.split("/")
    if key.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"chave de armazenamento inválida: {key!r}")
    return key


class LocalStorage:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / _safe_key(key)

    def put(self, key: str, data: bytes, content_type: str = "application/pdf") -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        except FileExistsError as exc:
            raise ObjectExistsError(key) from exc
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()


class GCSStorage:  # pragma: no cover - exige GCP
    def __init__(self, bucket: str):
        from google.cloud import storage as gcs

        self.bucket = gcs.Client().bucket(bucket)

    def put(self, key: str, data: bytes, content_type: str = "application/pdf") -> None:
        from google.api_core.exceptions import PreconditionFailed

        blob = self.bucket.blob(_safe_key(key))
        try:
            # if_generation_match=0: só grava se o objeto ainda não existir.
            blob.upload_from_string(data, content_type=content_type, if_generation_match=0)
        except PreconditionFailed as exc:
            raise ObjectExistsError(key) from exc

    def get(self, key: str) -> bytes:
        return self.bucket.blob(_safe_key(key)).download_as_bytes()

    def exists(self, key: str) -> bool:
        return self.bucket.blob(_safe_key(key)).exists()


def build_storage(settings) -> Storage:
    if settings.storage_backend == "gcs":
        return GCSStorage(settings.storage_gcs_bucket)
    return LocalStorage(settings.storage_local_path)
