"""Offline tests: every request goes to a local server that serves a chosen head."""
import asyncio
import base64
import json
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import x402_header_check as xc  # noqa: E402

CRLF = b"\r\n"


class Server:
    """Answers each request with respond(method, request_headers) -> raw head bytes."""

    def __init__(self, respond):
        self.respond, self.seen = respond, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.url = "http://127.0.0.1:%d/paid" % self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            conn, _ = self.sock.accept()
            try:
                data = b""
                while CRLF + CRLF not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                request = data.split(CRLF + CRLF)[0].split(CRLF)
                method = request[0].split(b" ")[0].decode()
                headers = {l.split(b":")[0].strip().lower().decode(): l.split(b":", 1)[1].strip().decode()
                           for l in request[1:] if b":" in l}
                self.seen.append((method, headers))
                conn.sendall(self.respond(method, headers) + b"{}")
            finally:
                conn.close()


def head(value=b"", extra=(), status=b"HTTP/1.1 402 Payment Required"):
    fields = [b"content-type: application/json", b"content-length: 2", b"connection: close"] + list(extra)
    if value is not None:
        fields.append(b"payment-required: " + value)
    return status + CRLF + CRLF.join(fields) + CRLF + CRLF


def challenge(**extra):
    doc = {"x402Version": 2, "error": "PAYMENT-SIGNATURE header is required",
           "resource": {"url": "https://seller.example/paid"},
           "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "10000"}]}
    doc.update(extra)
    return base64.b64encode(json.dumps(doc, separators=(",", ":")).encode())


def verdicts(value):
    server = Server(lambda m, h: head(value))
    result = xc.check(server.url, "GET")
    return {c["client"]: c for c in result["branches"][0]["clients"]}


# ---- each client's rule, at its measured boundary --------------------------------------------

def test_aiohttp_refuses_one_byte_past_8190_in_a_single_value():
    assert verdicts(b"A" * 8190)["aiohttp (Python)"]["ok"] is True
    assert verdicts(b"A" * 8191)["aiohttp (Python)"]["ok"] is False


def test_undici_counts_name_plus_value_across_every_header():
    # fixed fields: content-type 12+16, content-length 14+1, connection 10+5 = 58; payment-required 16
    room = 16383 - 58 - 16
    assert verdicts(b"A" * room)["fetch / undici (Node)"]["ok"] is True
    assert verdicts(b"A" * (room + 1))["fetch / undici (Node)"]["ok"] is False


def test_node_http_counts_the_status_reason_phrase_too():
    room = 16383 - len(b"Payment Required") - 58 - 16
    assert verdicts(b"A" * room)["node:http"]["ok"] is True
    assert verdicts(b"A" * (room + 1))["node:http"]["ok"] is False


def test_a_value_every_client_reads_is_ok_and_exits_zero(capsys):
    server = Server(lambda m, h: head(challenge()))
    assert xc.main([server.url]) == 0
    out = capsys.readouterr().out
    assert "FAILS" not in out and "PAYMENT-REQUIRED value:" in out


# ---- the rules agree with the real clients, where they are installed ------------------------

def _aiohttp_reads(url):
    aiohttp = pytest.importorskip("aiohttp")

    async def go():
        async with aiohttp.ClientSession() as s:
            async with s.get(url) as r:
                return r.status == 402
    try:
        return asyncio.run(go())
    except Exception:
        return False


@pytest.mark.parametrize("extra", [(), (b"x-pad: " + b"P" * 1000,)])
def test_the_aiohttp_rule_matches_aiohttp_itself(extra):
    for n in (8190, 8191):
        server = Server(lambda m, h, n=n: head(b"A" * n, extra))
        rule = {c["client"]: c for c in xc.check(server.url, "GET")["branches"][0]["clients"]}["aiohttp (Python)"]["ok"]
        assert _aiohttp_reads(server.url) is rule, n


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("client,code", [
    ("fetch / undici (Node)", "fetch(process.argv[1]).then(r=>process.stdout.write(String(r.status===402))).catch(()=>process.stdout.write('false'))"),
    ("node:http", "require('http').get(process.argv[1],r=>{process.stdout.write(String(r.statusCode===402));r.resume()}).on('error',()=>process.stdout.write('false'))"),
])
@pytest.mark.parametrize("extra,status", [
    ((), b"HTTP/1.1 402 Payment Required"),
    ((b"x-pad: " + b"P" * 1000,), b"HTTP/1.1 402 Payment Required"),
    ((), b"HTTP/1.1 402 Payment Required, see the PAYMENT-REQUIRED header"),
])
def test_the_node_rules_match_node_itself(client, code, extra, status):
    probe = Server(lambda m, h: head(b"", extra, status))
    clients = {c["client"]: c for c in xc.check(probe.url, "GET")["branches"][0]["clients"]}
    room = clients[client]["margin"]            # value bytes that still fit
    for n, expect in ((room, True), (room + 1, False)):
        server = Server(lambda m, h, n=n: head(b"A" * n, extra, status))
        out = subprocess.run(["node", "-e", code, server.url], capture_output=True, text=True, timeout=30).stdout
        assert (out.strip() == "true") is expect, (client, n)


# ---- what is fetched, and how ---------------------------------------------------------------

def test_auto_tries_post_when_get_does_not_answer_402():
    server = Server(lambda m, h: head(challenge()) if m == "POST" else head(None, status=b"HTTP/1.1 405 Method Not Allowed"))
    result = xc.check(server.url)
    assert result["measured"] and result["method"] == "POST"
    assert [m for m, _ in server.seen] == ["GET", "POST"]


def test_the_error_branch_is_measured_with_an_unpayable_signature():
    def respond(m, h):
        if "payment-signature" in h:
            return head(challenge(error="invalid payment: " + "x" * 400))
        return head(challenge())
    server = Server(respond)
    result = xc.check(server.url, "GET", error_branch=True)
    first, rejected = result["branches"]
    assert rejected["branch"] == "rejected payment" and rejected["value_bytes"] > first["value_bytes"]
    assert server.seen[1][1]["payment-signature"] == base64.b64encode(b"{}").decode()


def test_a_v1_seller_with_no_header_is_not_measured_and_exits_two(capsys):
    server = Server(lambda m, h: head(None))
    assert xc.main(["--method", "GET", server.url]) == 2
    assert "x402 v1 sends the challenge in the body" in capsys.readouterr().out


def test_a_refusal_outranks_an_unmeasured_url_in_the_exit_code():
    bad = Server(lambda m, h: head(b"A" * 9000))
    v1 = Server(lambda m, h: head(None))
    assert xc.main(["--method", "GET", v1.url, bad.url]) == 1


def test_a_non_402_is_stated():
    server = Server(lambda m, h: head(None, status=b"HTTP/1.1 200 OK"))
    result = xc.check(server.url)
    assert result["measured"] is False and "not 402" in result["reason"]


# ---- what the challenge carries -------------------------------------------------------------

def test_the_drill_down_names_the_part_to_fix():
    big = {"bazaar": {"schema": {"properties": {"input": "s" * 3000}}, "info": "i" * 200}}
    server = Server(lambda m, h: head(challenge(extensions=big)))
    ch = xc.check(server.url, "GET")["branches"][0]["challenge"]
    assert [p["path"] for p in ch["largest_part"]][:3] == ["extensions", "extensions.bazaar", "extensions.bazaar.schema"]
    assert list(ch["top_level"])[0] == "extensions"


def test_whitespace_in_the_served_json_is_reported_as_saving():
    doc = json.loads(base64.b64decode(challenge()))
    spaced = base64.b64encode(json.dumps(doc, indent=2).encode())
    server = Server(lambda m, h: head(spaced))
    ch = xc.check(server.url, "GET")["branches"][0]["challenge"]
    assert ch["served_value_bytes"] > ch["compact_value_bytes"]


def test_a_value_that_is_not_base64_json_is_said_so():
    server = Server(lambda m, h: head(b"not-base64!"))
    ch = xc.check(server.url, "GET")["branches"][0]["challenge"]
    assert ch["decodes"] is False
