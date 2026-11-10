"""Blob storage for module binaries: S3-compatible with server-side encryption.

Uploads are streamed in fixed chunks with a hard byte cap while sha256 is recomputed; the
hub never trusts the client-supplied digest. Downloads are served as short-lived presigned
GET URLs (the agent follows a 302).
"""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
from typing import IO, Any, Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.problems import too_large

CHUNK_BYTES = 1024 * 1024
SPOOL_BYTES = 8 * 1024 * 1024
PRESIGN_TTL_S = 300


class BlobError(Exception):
    """Raised when the blob backend fails; callers map it to 503."""


class BlobStore(Protocol):
    """Storage operations the hub needs for module binaries."""

    async def store(self, key: str, body: IO[bytes], size: int) -> None:
        """Store ``size`` bytes from ``body`` under ``key``."""
        ...

    async def delete(self, key: str) -> None:
        """Remove ``key`` (best-effort cleanup after a failed insert)."""
        ...

    async def presign_get(self, key: str) -> str:
        """Return a short-lived GET URL for ``key``."""
        ...

    async def ready(self) -> bool:
        """Return True when the bucket is reachable (readiness probe)."""
        ...


class S3BlobStore:
    """BlobStore backed by an S3-compatible bucket with AES256 SSE on every object."""

    def __init__(self, bucket: str, endpoint: str | None, region: str | None) -> None:
        """Create a boto3 client; credentials come from the standard AWS_* env vars."""
        self._bucket = bucket
        self._client: Any = boto3.client("s3", endpoint_url=endpoint, region_name=region)

    def _store_sync(self, key: str, body: IO[bytes]) -> None:
        """Blocking upload with SSE; run in a worker thread."""
        try:
            self._client.upload_fileobj(
                body, self._bucket, key, ExtraArgs={"ServerSideEncryption": "AES256"}
            )
        except (BotoCoreError, ClientError) as exc:
            raise BlobError(str(exc)) from exc

    async def store(self, key: str, body: IO[bytes], size: int) -> None:
        """Upload ``body`` without blocking the event loop."""
        del size  # size is enforced by the caller while streaming
        await asyncio.to_thread(self._store_sync, key, body)

    async def delete(self, key: str) -> None:
        """Delete an object; errors are raised as BlobError for the caller to log."""
        try:
            await asyncio.to_thread(self._client.delete_object, Bucket=self._bucket, Key=key)
        except (BotoCoreError, ClientError) as exc:
            raise BlobError(str(exc)) from exc

    async def presign_get(self, key: str) -> str:
        """Return a presigned GET URL valid for PRESIGN_TTL_S seconds."""
        try:
            return str(
                await asyncio.to_thread(
                    self._client.generate_presigned_url,
                    "get_object",
                    Params={"Bucket": self._bucket, "Key": key},
                    ExpiresIn=PRESIGN_TTL_S,
                )
            )
        except (BotoCoreError, ClientError) as exc:
            raise BlobError(str(exc)) from exc

    async def ready(self) -> bool:
        """Return True if HeadBucket succeeds."""
        try:
            await asyncio.to_thread(self._client.head_bucket, Bucket=self._bucket)
        except (BotoCoreError, ClientError):
            return False
        return True


def spool_and_hash(
    stream: IO[bytes], cap: int
) -> tuple[tempfile.SpooledTemporaryFile[bytes], str, int]:
    """Copy ``stream`` into a spooled temp file in chunks, hashing and enforcing ``cap``.

    Returns (rewound spool, sha256 hex, byte count). Raises ApiError 413 past ``cap``.
    """
    spool: tempfile.SpooledTemporaryFile[bytes] = tempfile.SpooledTemporaryFile(
        max_size=SPOOL_BYTES
    )
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise too_large(f"module exceeds {cap} bytes")
            digest.update(chunk)
            spool.write(chunk)
    except BaseException:
        spool.close()
        raise
    spool.seek(0)
    return spool, digest.hexdigest(), total
