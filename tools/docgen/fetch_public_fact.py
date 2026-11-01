"""SSRF-hardened public-fact fetcher (RULEBOOK L16, ENGINE_PLAN.md §4b).

Guards a server-originated request to a caller-supplied URL against being turned
into a blind-SSRF proxy against private/loopback/metadata addresses (originally from a since-retired internal rule set).

Fetches a public URL and returns a cited ``Fact``. Every check fails CLOSED: any ambiguity
(unresolvable host, private/loopback/link-local IP, non-http(s) scheme, redirect to a
non-allowlisted host, oversized/slow response, disallowed content-type) raises rather than
silently degrading. Connects to the resolved IP directly (no re-resolve TOCTOU / DNS
rebinding window) and re-validates host+IP on every redirect hop manually — the stdlib
``http.client`` is used instead of ``urllib.request`` so redirects are never followed
automatically.

Stdlib only; mypy --strict clean.
"""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from tools.docgen.models import Fact

_MAX_REDIRECTS = 5
_DEFAULT_MAX_BYTES = 1_000_000
_DEFAULT_TIMEOUT = 10.0
_ALLOWED_CONTENT_TYPES = ("text/html", "text/plain", "application/json")
# Cloud-metadata + link-local sentinel (blocked even though 169.254.0.0/16 is technically
# link-local and would already be caught, this is called out explicitly per the plan).
_METADATA_IP = ipaddress.ip_address("169.254.169.254")

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


class FetchError(RuntimeError):
    """Raised for any fetch failure or blocked condition (fail-closed)."""


@dataclass(frozen=True)
class _ResolvedTarget:
    scheme: str
    host: str
    port: int
    path_qs: str
    ip: str


def _is_blocked_ip(ip_str: str) -> bool:
    """True if the IP must never be connected to (RFC-1918, loopback, link-local, metadata, etc.)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> fail closed
    if ip == _METADATA_IP:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_pinned_ip(host: str, port: int) -> str:
    """Resolve ``host`` and return a single IP that is safe to connect to.

    Fail-closed: if resolution yields no safe address, or every candidate is blocked, raise.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise FetchError(f"DNS resolution failed for host {host!r}: {exc}") from exc
    if not infos:
        raise FetchError(f"DNS resolution returned no addresses for host {host!r}")
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = str(sockaddr[0])
        if _is_blocked_ip(ip_str):
            continue
        return ip_str
    raise FetchError(
        f"all resolved addresses for host {host!r} are blocked (private/loopback/link-local)"
    )


def _validate_and_split(url: str, allowlist: set[str]) -> _ResolvedTarget:
    """Parse ``url``, enforce scheme+allowlist, resolve to a pinned safe IP. Fail-closed throughout."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"blocked scheme: {parts.scheme!r} (only http/https allowed)")
    if not parts.hostname:
        raise FetchError("URL has no host")
    host = parts.hostname
    if host not in allowlist:
        raise FetchError(f"host {host!r} is not in the allowlist")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = _resolve_pinned_ip(host, port)
    path_qs = parts.path or "/"
    if parts.query:
        path_qs = f"{path_qs}?{parts.query}"
    return _ResolvedTarget(scheme=parts.scheme, host=host, port=port, path_qs=path_qs, ip=ip)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to a pinned IP but verifies TLS against the real hostname.

    Overriding ``connect()`` lets us open the raw socket against ``_pinned_ip`` (so we never
    re-resolve the hostname and reopen a DNS-rebinding window) while still passing the ORIGINAL
    hostname as ``server_hostname`` to ``wrap_socket`` for correct SNI + certificate hostname
    verification. Proxy tunneling is intentionally not supported (this fetcher never proxies).
    """

    _pinned_ip: str
    _verify_hostname: str

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # `_context` is set by the HTTPSConnection.__init__ `context=` kwarg; it is a private,
        # unannotated attribute in the stdlib type stubs, hence the targeted ignore below.
        context = self._context  # type: ignore[attr-defined]
        self.sock = context.wrap_socket(raw, server_hostname=self._verify_hostname)


def _open_connection(target: _ResolvedTarget, timeout: float) -> http.client.HTTPConnection:
    """Open a connection to the PINNED IP (never re-resolve the hostname — avoids TOCTOU/rebinding).

    The ``Host`` header still carries the original hostname (for virtual hosting / TLS SNI);
    the socket itself connects to the already-validated IP address. For HTTPS, TLS hostname
    verification still checks the ORIGINAL hostname (via ``server_hostname``), not the IP.
    """
    if target.scheme == "https":
        import ssl

        try:
            ctx = ssl.create_default_context()
        except Exception as exc:  # pragma: no cover - ssl module always present on cpython
            raise FetchError(f"failed to build TLS context: {exc}") from exc
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            target.host, target.port, timeout=timeout, context=ctx
        )
        conn._pinned_ip = target.ip  # type: ignore[attr-defined]
        conn._verify_hostname = target.host  # type: ignore[attr-defined]
    else:
        # Plain HTTP has no hostname verification concern; connect directly to the pinned IP.
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=timeout)
    return conn


def _sanitize_cache_filename(name: str) -> str:
    """Strip any path-traversal or unsafe characters from a proposed cache filename.

    Never returns a string containing ``..``, a leading ``.``, a path separator, or an empty
    result; collapses any disallowed character to ``_``. Callers should still join the result
    under a fixed, trusted cache directory (defense in depth — this alone is not the only
    guard against escaping that directory).
    """
    base = name.strip().replace("/", "_").replace("\\", "_")
    base = _UNSAFE_FILENAME_CHARS.sub("_", base)
    # Collapse any run of 2+ dots (path-traversal sequences) to a single underscore, then
    # strip any leading dot so the result can never start with "." or "..".
    base = re.sub(r"\.{2,}", "_", base)
    base = base.lstrip(".")
    if not base:
        base = "fact_cache"
    return base[:200]


def fetch(
    url: str,
    *,
    allowlist: set[str],
    max_bytes: int = _DEFAULT_MAX_BYTES,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Fact:
    """Fetch ``url`` and return a cited ``Fact``. Fails closed on every hardening check.

    Hardening (ENGINE_PLAN.md §4b; originally from a since-retired internal rule set):
    - Only http(s) schemes.
    - Host must be in ``allowlist``; DNS-resolved to a non-private/loopback/link-local/
      metadata IP, and the connection is made to that PINNED IP (no re-resolve TOCTOU).
    - Redirects (3xx with Location) are followed MANUALLY, up to ``_MAX_REDIRECTS`` hops,
      re-validating host + resolved IP + allowlist membership at every hop.
    - Response body capped at ``max_bytes``; total wall-clock capped at ``timeout`` seconds
      across the whole call (including all redirect hops).
    - Only an allowlisted response content-type is accepted.
    """
    deadline = time.monotonic() + timeout
    current_url = url
    last_target: _ResolvedTarget | None = None

    for _hop in range(_MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("fetch exceeded total time budget")
        target = _validate_and_split(current_url, allowlist)
        last_target = target
        conn = _open_connection(target, timeout=remaining)
        try:
            conn.request(
                "GET",
                target.path_qs,
                headers={"Host": target.host, "User-Agent": "CredMgr-docgen-fetcher/1.0"},
            )
            resp = conn.getresponse()
            status = resp.status
            if 300 <= status < 400:
                location = resp.getheader("Location")
                resp.read(0)  # drain nothing extra; body of a redirect is irrelevant
                if not location:
                    raise FetchError(f"redirect status {status} with no Location header")
                # Resolve relative redirects against the current URL.
                next_url = _join_redirect(current_url, location)
                current_url = next_url
                continue
            if status < 200 or status >= 300:
                raise FetchError(f"unexpected HTTP status {status} from {current_url!r}")

            content_type = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if content_type not in _ALLOWED_CONTENT_TYPES:
                raise FetchError(f"blocked content-type: {content_type!r}")

            body = _read_capped(resp, max_bytes)
            text = body.decode("utf-8", errors="replace")
            return Fact(
                url=current_url,
                value=text,
                retrieved=datetime.now(UTC).isoformat(),
                kind="scraped",
            )
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    raise FetchError(
        f"too many redirects (> {_MAX_REDIRECTS}) starting from {url!r}, last hop {last_target}"
    )


def _join_redirect(base_url: str, location: str) -> str:
    """Resolve a (possibly relative) redirect Location header against the base URL."""
    loc_parts = urlsplit(location)
    if loc_parts.scheme and loc_parts.netloc:
        return location
    base_parts = urlsplit(base_url)
    scheme = loc_parts.scheme or base_parts.scheme
    netloc = loc_parts.netloc or base_parts.netloc
    path = loc_parts.path or "/"
    if not path.startswith("/"):
        # relative path resolution against the base path's directory
        base_dir = base_parts.path.rsplit("/", 1)[0]
        path = f"{base_dir}/{path}"
    return urlunsplit((scheme, netloc, path, loc_parts.query, ""))


def _read_capped(resp: http.client.HTTPResponse, max_bytes: int) -> bytes:
    """Read the response body, raising if it exceeds ``max_bytes`` (fail-closed on oversize)."""
    chunks: list[bytes] = []
    total = 0
    chunk_size = 65536
    while True:
        chunk = resp.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"response exceeded max_bytes cap ({max_bytes})")
        chunks.append(chunk)
    return b"".join(chunks)
