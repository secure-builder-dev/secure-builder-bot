"""One HTTPS POST, standard library only: the transport both real providers share.

`http.client`, not `urllib.request`: the URL comes from the config (a mirror for an air-gapped
install), and http.client opens exactly the scheme it is given — https, or http for a self-hosted
server on the user's own network — with no file: or ftp: handler to reach by accident. A proxy named
by HTTPS_PROXY is used through a CONNECT tunnel, so TLS is end to end; NO_PROXY is honoured by host
suffix. Errors name the host and the kind of failure, never a header (the key travels in one).
"""

from __future__ import annotations

import http.client
import os
import ssl
from collections.abc import Callable, Mapping
from urllib.parse import SplitResult, urlsplit

from . import ProviderError

MAX_RESPONSE_BYTES = 8_000_000


def _no_proxy(host: str, environ: Mapping[str, str]) -> bool:
    raw = environ.get("NO_PROXY") or environ.get("no_proxy") or ""
    for entry in (e.strip().lstrip(".") for e in raw.split(",")):
        if entry == "*" or (entry and (host == entry or host.endswith("." + entry))):
            return True
    return False


def connect(parts: SplitResult, timeout: float, environ: Mapping[str, str]) -> http.client.HTTPConnection:
    """A connection for the URL, not yet opened: direct, or through the HTTPS proxy's tunnel."""
    host = parts.hostname or ""
    if parts.scheme == "http":
        return http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
    context = ssl.create_default_context()
    proxy = environ.get("HTTPS_PROXY") or environ.get("https_proxy")
    if proxy and not _no_proxy(host, environ):
        p = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        conn = http.client.HTTPSConnection(p.hostname or "", p.port or 3128, timeout=timeout, context=context)
        conn.set_tunnel(host, parts.port or 443)
        return conn
    return http.client.HTTPSConnection(host, parts.port or 443, timeout=timeout, context=context)


def post_json(url: str, headers: Mapping[str, str], body: bytes, timeout: float,
              connect: Callable = connect, environ: Mapping[str, str] | None = None) -> tuple[int, bytes]:
    """POST the body; the status and the response body. An unreachable endpoint raises ProviderError."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    conn = None
    try:
        conn = connect(parts, timeout, os.environ if environ is None else environ)
        conn.request("POST", path, body, dict(headers))
        resp = conn.getresponse()
        return resp.status, resp.read(MAX_RESPONSE_BYTES)
    except (OSError, http.client.HTTPException) as e:
        raise ProviderError(f"the model endpoint could not be reached at {parts.hostname}: {type(e).__name__}") from None
    finally:
        if conn is not None:
            conn.close()
