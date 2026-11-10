"""Agent identity from a SPIFFE URI SAN forwarded by the ingress (mTLS path).

The ingress terminates client certificates and forwards them in X-Forwarded-Client-Cert
(XFCC). That header is only believed when HUB_TRUST_FORWARDED_CERT=1 (ingress verified
deployment). Otherwise it is stripped from every request before any handler runs, so a
client cannot spoof an agent identity by sending it directly. Direct in-pod TLS termination
is not wired (chart: ingress.mtls.mode=passthrough is an open question).
"""

from __future__ import annotations

import uuid

from werkzeug.datastructures import Headers

from app.config import Settings

XFCC_HEADER = "X-Forwarded-Client-Cert"


def strip_untrusted_identity(headers: Headers, settings: Settings) -> None:
    """Remove the forwarded-cert header unless the ingress is trusted."""
    if settings.trust_forwarded_cert:
        return
    for key in [k for k in headers.keys() if k.lower() == XFCC_HEADER.lower()]:
        del headers[key]


def _uri_sans(xfcc: str) -> list[str]:
    """Extract every URI= value from an XFCC header (elements separated by ';' or ',')."""
    uris: list[str] = []
    for element in xfcc.replace(",", ";").split(";"):
        key, _, value = element.strip().partition("=")
        if key.strip().upper() == "URI" and value:
            uris.append(value.strip().strip('"'))
    return uris


def mtls_agent_id(headers: Headers, settings: Settings) -> uuid.UUID | None:
    """Return the agent public id from a trusted SPIFFE URI SAN, or None.

    Only ids under ``settings.spiffe_prefix`` count; the suffix must be a UUID.
    """
    if not settings.trust_forwarded_cert:
        return None
    xfcc = headers.get(XFCC_HEADER)
    if not xfcc:
        return None
    for uri in _uri_sans(str(xfcc)):
        if uri.startswith(settings.spiffe_prefix):
            suffix = uri[len(settings.spiffe_prefix) :]
            try:
                return uuid.UUID(suffix)
            except ValueError:
                return None
    return None
