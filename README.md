# x402-header-check

Checks whether HTTP clients can read an x402 resource's payment challenge.

An x402 v2 seller puts its whole challenge in one response header,
`PAYMENT-REQUIRED`, which is base64 of JSON. HTTP clients have header limits,
and none of them truncates a header that is too large: they fail the whole
response. A buyer on such a client never sees the offer, and nothing in the
seller's logs says why.

```
python x402_header_check.py https://api.satledger.org/x402/receipt
```

```
https://api.satledger.org/x402/receipt
  challenge (GET 402): head 4,592 B, 14 headers
    PAYMENT-REQUIRED value: 4,160 B
    ok    aiohttp (Python)               4,160 / 8,190      each header value <= 8,190 B
    ok    fetch / undici (Node)          4,503 / 16,383     sum of name + value over all headers <= 16,383 B
    ok    node:http                      4,519 / 16,383     status reason phrase + sum of name + value <= 16,383 B
    ok    requests / urllib (Python)     4,178 / 65,534     each line <= 65,534 B, at most 99 header fields
    ok    Go net/http                    4,592 / 10,485,760 whole head <= 10 MiB (documented default)
    note  httpx / h11: no fixed limit when the head arrives in one piece (measured past 80,000 B); its 16,384 B buffer applies only while a head is still arriving
    challenge: x402Version 2, 3,120 B of JSON; top level: extensions 2,232, accepts 464, resource 323, error 38, x402Version 1
    largest part: extensions 2,232 B (72%) > bazaar 2,221 B (100%) > schema 1,216 B (55%) > properties 1,107 B (91%)
```

The last line is the fix list: the part of the challenge that makes it big.

## Options

| Option | Effect |
| --- | --- |
| `--error-branch` | Also sends an unpayable `PAYMENT-SIGNATURE` (base64 of `{}`) and measures the rejection. A seller that echoes the failure reason into the challenge can be larger there than on the first 402. |
| `--method GET\|POST` | The default, `auto`, tries GET, then POST if GET does not answer 402. |
| `--json` | One JSON object per URL, for scripts. |

Exit codes: `0` every client reads the head, `1` at least one client refuses
it, `2` nothing was measured (network error, no 402, or no `PAYMENT-REQUIRED`
header; x402 v1 sends the challenge in the body, where these limits do not
apply).

The tool needs Python 3.8+ and the standard library only. It reads the response head
exactly as it arrives over HTTP/1.1 and never sends a payment that could
settle. A redirect is reported with its target, not followed.

## The limits are measured

Each rule was found by serving a 402 of known size to the client and
bisecting for the largest it accepts. The rule is the one that held when the
rest of the head was varied: an extra header, and a longer status reason
phrase.

| Client | Version measured | Rule |
| --- | --- | --- |
| aiohttp | 3.14.3 | each header value ≤ 8,190 B (names ≤ 8,180 B and the reason phrase ≤ 8,190 B, also measured; an x402 head never nears them) |
| fetch / undici | Node 24.13 | sum of name + value over all headers ≤ 16,383 B |
| node:http | Node 24.13 | status reason phrase + sum of name + value ≤ 16,383 B |
| requests, urllib (`http.client`) | CPython 3.14 | each line ≤ 65,534 B, at most 99 header fields |
| httpx (h11) | httpx 0.28.1, h11 0.16.0 | no fixed limit when the head arrives in one piece (measured past 80,000 B); its 16,384 B buffer applies only while a head is still arriving |
| Go net/http | — | 10 MiB, the documented default; not measured |

The tests serve heads either side of each boundary to the real aiohttp,
Node and `http.client` clients (the first two when installed), so a client release that changes its
limit fails the suite instead of silently making this tool wrong.

HTTP/2 is not measured. There the limit is `SETTINGS_MAX_HEADER_LIST_SIZE`,
which some servers and clients ignore and others enforce.

## Tests

```
pip install pytest
python -m pytest tests -q
```

They run offline against a local server. The real-client cross-checks skip
when aiohttp or Node is not installed.

## Licence

Apache-2.0. See `LICENSE`.
