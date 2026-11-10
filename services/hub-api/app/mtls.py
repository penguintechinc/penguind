"""Agent identity from a SPIFFE URI SAN forwarded by the ingress (mTLS path).

The ingress terminates client certificates and forwards them in X-Forwarded-Client-Cert
(XFCC). The header is believed only when BOTH hold:

1. HUB_TRUST_FORWARDED_CERT=1, and
2. the TCP peer (request.remote_addr) is inside HUB_TRUSTED_PROXY_CIDRS (empty = refuse).

The ingress MUST overwrite the header rather than append to it: Envoy
``forward_client_cert_details: SANITIZE_SET`` (or the equivalent overwrite mode), so a
client-supplied XFCC never reaches the hub. Accepted XFCC holds exactly one element with
exactly one URI; anything else is rejected. The header is removed from every request before
any handler runs.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Network, IPv6Network, ip_address

from werkzeug.datastructures import Headers

from app.config import Settings

XFCC_HEADER = "X-Forwarded-Client-Cert"
SPIFFE_SCHEME = "spiffe://"
_FORBIDDEN_URI_CHARS = frozenset(' "\t\r\n')


class MalformedXfccError(ValueError):
    """Raised when an XFCC header cannot be parsed unambiguously."""


def _split_unquoted(text: str, sep: str) -> list[str]:
    """Split ``text`` on ``sep`` outside double-quoted spans; an open quote is malformed."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
        if ch == sep and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if in_quotes:
        raise MalformedXfccError("unbalanced quote")
    parts.append("".join(current))
    return parts


def single_spiffe_uri(xfcc: str) -> str | None:
    """Return the only URI of a single-element XFCC header, or None if it is not exactly one.

    Quoted values are honoured, so a comma or semicolon inside quotes never splits an element.
    The URI must start with ``spiffe://`` and contain no whitespace or quotes.
    """
    try:
        elements = [e for e in _split_unquoted(xfcc, ",") if e.strip()]
        if len(elements) != 1:
            return None
        pairs = _split_unquoted(elements[0], ";")
    except MalformedXfccError:
        return None
    uris: list[str] = []
    for pair in pairs:
        key, sep, value = pair.strip().partition("=")
        if sep and key.strip().lower() == "uri":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            uris.append(value)
    if len(uris) != 1:
        return None
    uri = uris[0]
    if not uri.startswith(SPIFFE_SCHEME) or any(c in _FORBIDDEN_URI_CHARS for c in uri):
        return None
    return uri


def trusted_peer(remote_addr: str | None, cidrs: Iterable[IPv4Network | IPv6Network]) -> bool:
    """Return True only if the TCP peer address lies inside a trusted proxy network."""
    if not remote_addr:
        return False
    try:
        address = ip_address(remote_addr)
    except ValueError:
        return False
    return any(address in network for network in cidrs)


def take_forwarded_identity(
    headers: Headers, settings: Settings, remote_addr: str | None
) -> str | None:
    """Remove the XFCC header and return its SPIFFE URI only when the ingress is trusted.

    Returns None when trust is off, the peer is not a trusted proxy, or the header is
    malformed or ambiguous. The header is removed in every case so handlers never see it.
    """
    raw = headers.get(XFCC_HEADER)
    for key in [k for k in headers.keys() if k.lower() == XFCC_HEADER.lower()]:
        del headers[key]
    if raw is None or not settings.trust_forwarded_cert:
        return None
    if not trusted_peer(remote_addr, settings.trusted_proxy_cidrs):
        return None
    return single_spiffe_uri(str(raw))
