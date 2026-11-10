"""Optional minisign verification of uploaded module signatures (early rejection only).

The hub never signs. When HUB_TRUSTED_PUBKEYS is configured, an upload whose signature does
not verify against one of those public keys is rejected before storage; agents still verify
independently against their own trusted keys. Signed message format:
``penguin-wasm-module/v1\\nid=<id>\\nversion=<version>\\nsha256=<sha256>\\n``.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_PUBKEY_ALG = b"Ed"
_SIG_ALGS = (b"Ed", b"ED")
_PUBKEY_LEN = 42
_SIG_LEN = 74
_KEYID_LEN = 8


class SignatureInvalidError(Exception):
    """Raised when a minisign signature or public key cannot be verified."""


@dataclass(slots=True, frozen=True)
class MinisignKey:
    """A parsed minisign public key: 8-byte key id and 32-byte Ed25519 key."""

    key_id: bytes
    key: Ed25519PublicKey

    @classmethod
    def parse(cls, text: str) -> MinisignKey:
        """Parse a base64 minisign public key line (``Ed`` algorithm only)."""
        try:
            raw = base64.b64decode(text.strip(), validate=True)
        except ValueError as exc:
            raise SignatureInvalidError("public key is not base64") from exc
        if len(raw) != _PUBKEY_LEN or raw[:2] != _PUBKEY_ALG:
            raise SignatureInvalidError("public key has an unsupported format")
        return cls(raw[2:10], Ed25519PublicKey.from_public_bytes(raw[10:]))


def module_message(module_id: str, version: str, sha256: str) -> bytes:
    """Return the exact text that the offline signer signs for a module version."""
    return f"penguin-wasm-module/v1\nid={module_id}\nversion={version}\nsha256={sha256}\n".encode()


def _signature_blob(signature: str) -> bytes:
    """Extract the 74-byte minisign signature blob from a bare or full minisig text."""
    # A full .minisig is: untrusted comment, signature, trusted comment, global signature.
    # The signature is the first line that is not a comment; the global signature that ends
    # the file is a different 64-byte blob and must never be picked.
    lines = [line.strip() for line in signature.strip().splitlines() if line.strip()]
    payload = [
        ln for ln in lines if not ln.lower().startswith(("untrusted comment:", "trusted comment:"))
    ]
    candidate = payload[0] if payload else ""
    try:
        raw = base64.b64decode(candidate, validate=True)
    except ValueError as exc:
        raise SignatureInvalidError("signature is not base64") from exc
    if len(raw) != _SIG_LEN or raw[:2] not in _SIG_ALGS:
        raise SignatureInvalidError("signature has an unsupported format")
    return raw


def verify_module_signature(
    keys: tuple[MinisignKey, ...], module_id: str, version: str, sha256: str, signature: str
) -> bool:
    """Return True if any trusted key verifies the signature over the module message."""
    blob = _signature_blob(signature)
    alg, key_id, sig = blob[:2], blob[2:10], blob[10:]
    message = module_message(module_id, version, sha256)
    for key in keys:
        if key.key_id != key_id:
            continue
        # "ED" = prehashed (minisign default): the signature covers blake2b-512(message).
        data = hashlib.blake2b(message, digest_size=64).digest() if alg == b"ED" else message
        try:
            key.key.verify(sig, data)
        except InvalidSignature:
            continue
        return True
    return False
