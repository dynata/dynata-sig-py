"""Dynata signing-string and signature generation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from .canonicalize import build_canonical_url


@dataclass(frozen=True)
class SigningHeaders:
    """Dynata signature envelope values."""

    dynata_expiration: str
    dynata_access_key: str
    dynata_signature: str
    dynata_signing_string: str


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _hmac_sha256_hex(key: str, message: str) -> str:
    return hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_signing_string(method: str, url: str, body: str | bytes | None = "") -> str:
    """Return lowercase SHA-256 hex digest of METHOD + canonical URL + body."""

    if method is None:
        raise TypeError("method must not be null")
    if not method:
        raise ValueError("method must not be blank")
    if url is None:
        raise TypeError("url must not be null")
    canonical_url = build_canonical_url(url)

    body_text = ""
    if isinstance(body, bytes):
        body_text = body.decode("utf-8")
    elif body:
        body_text = body

    return _sha256_hex(method + canonical_url + body_text)


def create_signature(
    signing_string_hash: str,
    expiration: str,
    access_key: str,
    secret_key: str,
) -> str:
    """Create request signature via 3-step HMAC-SHA256 chain."""

    if signing_string_hash is None:
        raise TypeError("signing_string_hash must not be null")
    if expiration is None:
        raise TypeError("expiration must not be null")
    if access_key is None:
        raise TypeError("access_key must not be null")
    if secret_key is None:
        raise TypeError("secret_key must not be null")

    first = _hmac_sha256_hex(expiration, signing_string_hash)
    second = _hmac_sha256_hex(access_key, first)
    return _hmac_sha256_hex(secret_key, second)


def sign_request(
    method: str,
    url: str,
    body: str | bytes | None,
    expiration: str,
    access_key: str,
    secret_key: str,
) -> SigningHeaders:
    """Compute Dynata signing string and signature values."""

    if not access_key or not access_key.strip():
        raise ValueError("access_key must not be blank")
    if not secret_key or not secret_key.strip():
        raise ValueError("secret_key must not be blank")
    if not expiration or not expiration.strip():
        raise ValueError("expiration must not be blank")

    signing_string_hash = generate_signing_string(method=method, url=url, body=body)
    signature = create_signature(
        signing_string_hash=signing_string_hash,
        expiration=expiration,
        access_key=access_key,
        secret_key=secret_key,
    )
    return SigningHeaders(
        dynata_expiration=expiration,
        dynata_access_key=access_key,
        dynata_signature=signature,
        dynata_signing_string=signing_string_hash,
    )
