"""URL canonicalization for Dynata request signing."""

from __future__ import annotations

import posixpath
import re
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")


def build_canonical_url(raw_url: str) -> str:
    """Build canonical URL used by Dynata signing.

    Behavior follows dynata-sig-java / dynata-sig-go:
    - split by first "?"
    - normalize path
    - parse only query pairs containing "="
    - keep the last value for duplicate keys
    - decode and then RFC3986-encode query key/value
    - sort keys lexicographically
    - always include a trailing "?"
    """

    if raw_url is None:
        raise TypeError("url must not be null")
    if not raw_url.strip():
        raise ValueError("url must not be blank")

    split_idx = raw_url.find("?")
    path_part = raw_url if split_idx < 0 else raw_url[:split_idx]
    query_part = "" if split_idx < 0 else raw_url[split_idx + 1 :]

    canonical_path = _build_canonical_path(path_part)
    canonical_query = _build_canonical_query_string(query_part)
    return f"{canonical_path}?{canonical_query}"


def _build_canonical_path(raw_path: str) -> str:
    parsed = urlsplit(raw_path)

    # Opaque URIs are not expected in this library; return as-is for parity with Go behavior.
    if parsed.scheme and not parsed.netloc and parsed.path and not parsed.path.startswith("/"):
        return raw_path

    normalized = _normalize_escaped_path(parsed.path)
    if not parsed.scheme and not parsed.netloc:
        return normalized

    return urlunsplit((parsed.scheme, parsed.netloc, normalized, "", ""))


def _normalize_escaped_path(escaped_path: str) -> str:
    if not escaped_path:
        return ""

    trailing_slash = escaped_path.endswith("/") and escaped_path != "/"
    normalized = posixpath.normpath(escaped_path)
    if normalized == ".":
        normalized = ""
    if escaped_path.startswith("/") and not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if trailing_slash and not normalized.endswith("/"):
        normalized = f"{normalized}/"
    return normalized


def _strict_url_decode(value: str) -> str:
    if _INVALID_PERCENT_ENCODING.search(value):
        raise ValueError(f"not decodable: {value}")
    try:
        return unquote_plus(value, encoding="utf-8", errors="strict")
    except Exception as exc:  # pragma: no cover - defensive parity path
        raise ValueError(f"not decodable: {value}") from exc


def _percent_encode_rfc3986(value: str) -> str:
    return quote(value, safe="-_.~")


def _build_canonical_query_string(raw_query: str) -> str:
    values_by_key: dict[str, str] = {}
    for pair in raw_query.split("&"):
        eq_idx = pair.find("=")
        if eq_idx < 0:
            continue
        key = pair[:eq_idx]
        value = pair[eq_idx + 1 :]
        values_by_key[key] = value

    canonical_pairs: list[str] = []
    for key in sorted(values_by_key):
        decoded_key = _strict_url_decode(key)
        decoded_value = _strict_url_decode(values_by_key[key])
        encoded_key = _percent_encode_rfc3986(decoded_key)
        encoded_value = _percent_encode_rfc3986(decoded_value)
        canonical_pairs.append(f"{encoded_key}={encoded_value}")

    return "&".join(canonical_pairs)
