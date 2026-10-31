#!/usr/bin/env python3
"""Check an x402 resource's 402 response head against real HTTP client limits.

An x402 v2 seller puts its whole payment challenge in one response header,
PAYMENT-REQUIRED, base64 of JSON. Clients do not truncate a header that is
too large: they fail the whole response, so the buyer never sees the offer.
This tool fetches the 402 exactly as it arrives over HTTP/1.1, measures it
against each client's limit, and shows which part of the challenge is large.

    python x402_header_check.py https://example.com/paid-route
    python x402_header_check.py --error-branch --json URL [URL ...]

The limits are measured, not taken from documentation, by serving a 402 of
known size to each client and bisecting for the largest it accepts
(aiohttp 3.14.3, Node 24.13 fetch/undici and node:http, httpx 0.28.1 with
h11 0.16.0, CPython 3.14 http.client). Each rule below is the one that held
when the rest of the head was varied. Go's net/http is the documented
default, not a measurement.

Exit codes: 0 every client accepts the head; 1 at least one client refuses
it; 2 nothing was measured (network error, no 402, no PAYMENT-REQUIRED).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

__version__ = "0.1.0"
USER_AGENT = "x402-header-check/%s" % __version__
MAX_HEAD = 1 << 20          # read at most 1 MiB of response head
CRLF = b"\r\n"

# A probe payment that no seller can settle: base64 of "{}". It exists only to
# reach the branch that answers a rejected payment, whose head can be larger.
PROBE_SIGNATURE = base64.b64encode(b"{}").decode("ascii")

Header = Tuple[bytes, bytes]


def _aiohttp(status: bytes, headers: List[Header]) -> Tuple[int, int, str]:
    worst = max([len(status)] + [max(len(n), len(v)) for n, v in headers])
    return worst, 8190, "each header value (and name, and the status line) <= 8,190 B"


def _undici(status: bytes, headers: List[Header]) -> Tuple[int, int, str]:
    return sum(len(n) + len(v) for n, v in headers), 16383, "sum of name + value over all headers <= 16,383 B"


def _node_http(status: bytes, headers: List[Header]) -> Tuple[int, int, str]:
    reason = status.split(b" ", 2)[2] if status.count(b" ") >= 2 else b""
    return (len(reason) + sum(len(n) + len(v) for n, v in headers), 16383,
            "status reason phrase + sum of name + value <= 16,383 B")


def _http_client(status: bytes, headers: List[Header]) -> Tuple[int, int, str]:
    worst = max([len(status)] + [len(n) + 2 + len(v) for n, v in headers])
    return worst, 65534, "each line <= 65,534 B (and at most 100 headers)"


def _go(status: bytes, headers: List[Header]) -> Tuple[int, int, str]:
    total = len(status) + 2 + sum(len(n) + 2 + len(v) + 2 for n, v in headers) + 2
    return total, 10 << 20, "whole head <= 10 MiB (documented default)"


CLIENTS = [
    ("aiohttp (Python)", _aiohttp),
    ("fetch / undici (Node)", _undici),
    ("node:http", _node_http),
    ("requests / urllib (Python)", _http_client),
    ("Go net/http", _go),
]
H11_NOTE = ("httpx / h11: no fixed limit when the head arrives in one piece (measured past 80,000 B); "
            "its 16,384 B buffer applies only while a head is still arriving")


def fetch_head(url: str, method: str, body: bytes, extra: Dict[str, str], timeout: float) -> Tuple[bytes, List[Header]]:
    """The response's status line and header fields, exactly as sent, over HTTP/1.1."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("not an http(s) URL: %r" % url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    host = parts.hostname + ("" if parts.port in (None, 80, 443) else ":%d" % parts.port)
    lines = ["%s %s HTTP/1.1" % (method, target), "Host: %s" % host, "User-Agent: %s" % USER_AGENT,
             "Accept: application/json", "Connection: close"]
    if method == "POST":
        lines += ["Content-Type: application/json", "Content-Length: %d" % len(body)]
    lines += ["%s: %s" % kv for kv in extra.items()]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body if method == "POST" else b"")
    raw = socket.create_connection((parts.hostname, port), timeout=timeout)
    try:
        if parts.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
        raw.sendall(request)
        data = b""
        while CRLF + CRLF not in data:
            chunk = raw.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_HEAD:
                raise ValueError("response head larger than %d bytes" % MAX_HEAD)
    finally:
        raw.close()
    head = data.split(CRLF + CRLF, 1)[0]
    status, *fields = head.split(CRLF)
    headers = []
    for field in fields:
        name, _, value = field.partition(b":")
        headers.append((name.strip(), value.strip(b" \t")))
    return status, headers


def _status_code(status: bytes) -> Optional[int]:
    parts = status.split(b" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


def _size_tree(value: Any, path: str, out: List[Tuple[int, str]]) -> int:
    """Rendered JSON size of each subtree, collected as (bytes, path)."""
    size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    out.append((size, path or "(whole challenge)"))
    if isinstance(value, dict):
        for key, child in value.items():
            _size_tree(child, "%s.%s" % (path, key) if path else key, out)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _size_tree(child, "%s[%d]" % (path, i), out)
    return size


def _rendered(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _drill(doc: Any) -> List[Dict[str, Any]]:
    """Follow the largest child down while it is most of its parent: the part to fix."""
    chain, node, path = [], doc, ""
    while isinstance(node, (dict, list)) and node and len(chain) < 4:
        items = list(node.items()) if isinstance(node, dict) else [("[%d]" % i, v) for i, v in enumerate(node)]
        key, child = max(items, key=lambda kv: _rendered(kv[1]))
        share = _rendered(child) / max(1, _rendered(node))
        if chain and share < 0.4:
            break
        path = (path + ("" if key.startswith("[") else ".") + key) if path else key
        chain.append({"path": path, "json_bytes": _rendered(child), "share_of_parent": round(share, 2)})
        node = child
    return chain


def breakdown(value: bytes) -> Dict[str, Any]:
    """What the challenge carries and which parts are large."""
    try:
        doc = json.loads(base64.b64decode(value, validate=True))
    except Exception as exc:
        return {"decodes": False, "reason": "not base64 of JSON: %s" % exc}
    if not isinstance(doc, dict):
        return {"decodes": False, "reason": "decodes to %s, not an object" % type(doc).__name__}
    sizes: List[Tuple[int, str]] = []
    total = _size_tree(doc, "", sizes)
    compact = len(base64.b64encode(json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    top = {k: n for n, k in sizes if k in doc}
    return {"decodes": True, "x402Version": doc.get("x402Version"), "json_bytes": total,
            "top_level": dict(sorted(top.items(), key=lambda kv: -kv[1])),
            "largest_part": _drill(doc),
            "compact_value_bytes": compact, "served_value_bytes": len(value),
            "error_bytes": len(json.dumps(doc.get("error", ""), ensure_ascii=False).encode("utf-8")) - 2
            if isinstance(doc.get("error"), str) else 0}


def judge(status: bytes, headers: List[Header]) -> List[Dict[str, Any]]:
    out = []
    for name, rule in CLIENTS:
        measured, limit, text = rule(status, headers)
        out.append({"client": name, "measured": measured, "limit": limit, "ok": measured <= limit,
                    "margin": limit - measured, "rule": text})
    return out


def check(url: str, method: str = "auto", body: bytes = b"{}", error_branch: bool = False,
          timeout: float = 20.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"url": url, "measured": False}
    methods = ["GET", "POST"] if method == "auto" else [method]
    try:
        for m in methods:
            status, headers = fetch_head(url, m, body, {}, timeout)
            if _status_code(status) == 402:
                break
        result.update(method=m, status=_status_code(status))
        branches = [("challenge", status, headers)]
        if error_branch and _status_code(status) == 402:
            e_status, e_headers = fetch_head(url, m, body, {"PAYMENT-SIGNATURE": PROBE_SIGNATURE}, timeout)
            branches.append(("rejected payment", e_status, e_headers))
    except Exception as exc:
        result["reason"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    if result["status"] != 402:
        result["reason"] = "answered %s, not 402, to %s" % (result["status"], "/".join(methods))
        return result
    result["branches"] = []
    for label, b_status, b_headers in branches:
        value = next((v for n, v in b_headers if n.lower() == b"payment-required"), None)
        branch = {"branch": label, "status": _status_code(b_status), "head_bytes":
                  len(b_status) + 2 + sum(len(n) + 2 + len(v) + 2 for n, v in b_headers) + 2,
                  "header_count": len(b_headers)}
        if value is None:
            branch["reason"] = ("no PAYMENT-REQUIRED header (x402 v1 sends the challenge in the body, "
                                "where these limits do not apply)")
        else:
            branch.update(value_bytes=len(value), challenge=breakdown(value), clients=judge(b_status, b_headers))
        result["branches"].append(branch)
    measured = [b for b in result["branches"] if "clients" in b]
    result["measured"] = bool(measured)
    result["ok"] = all(c["ok"] for b in measured for c in b["clients"]) if measured else None
    if not measured:
        result["reason"] = result["branches"][0]["reason"]
    return result


def render(result: Dict[str, Any]) -> str:
    lines = [result["url"]]
    if not result["measured"]:
        lines.append("  not measured: %s" % result.get("reason", "unknown"))
        return "\n".join(lines)
    for b in result["branches"]:
        lines.append("  %s (%s %s): head %s B, %d headers" % (b["branch"], result["method"], b["status"],
                                                             format(b["head_bytes"], ","), b["header_count"]))
        if "clients" not in b:
            lines.append("    %s" % b["reason"])
            continue
        lines.append("    PAYMENT-REQUIRED value: %s B" % format(b["value_bytes"], ","))
        for c in b["clients"]:
            verdict = "ok   " if c["ok"] else "FAILS"
            lines.append("    %s %-27s %8s / %-10s %s" % (verdict, c["client"], format(c["measured"], ","),
                                                        format(c["limit"], ","), c["rule"]))
        lines.append("    note  %s" % H11_NOTE)
        ch = b["challenge"]
        if not ch["decodes"]:
            lines.append("    challenge: %s" % ch["reason"])
            continue
        lines.append("    challenge: x402Version %s, %s B of JSON; top level: %s" % (
            ch["x402Version"], format(ch["json_bytes"], ","),
            ", ".join("%s %s" % (k, format(n, ",")) for k, n in ch["top_level"].items())))
        if ch["largest_part"]:
            lines.append("    largest part: %s" % " > ".join("%s %s B (%d%%)" % (
                p["path"].rsplit(".", 1)[-1], format(p["json_bytes"], ","), round(100 * p["share_of_parent"]))
                for p in ch["largest_part"]))
        if ch["served_value_bytes"] > ch["compact_value_bytes"]:
            lines.append("    compact JSON would save %s B (served %s, compact %s)" % (
                format(ch["served_value_bytes"] - ch["compact_value_bytes"], ","),
                format(ch["served_value_bytes"], ","), format(ch["compact_value_bytes"], ",")))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("urls", nargs="+", metavar="URL")
    ap.add_argument("--method", default="auto", choices=["auto", "GET", "POST"],
                    help="auto tries GET, then POST if GET does not answer 402")
    ap.add_argument("--body", default="{}", help="POST body (default {})")
    ap.add_argument("--error-branch", action="store_true",
                    help="also send an unpayable PAYMENT-SIGNATURE and measure the rejection's head")
    ap.add_argument("--json", action="store_true", help="one JSON object per URL")
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args(argv)
    codes = []
    for url in args.urls:
        result = check(url, args.method, args.body.encode("utf-8"), args.error_branch, args.timeout)
        print(json.dumps(result) if args.json else render(result))
        codes.append(2 if not result["measured"] else 0 if result["ok"] else 1)
    # A refusal anywhere is the finding; an unmeasured URL only when nothing refused.
    return 1 if 1 in codes else max(codes)


if __name__ == "__main__":
    sys.exit(main())
