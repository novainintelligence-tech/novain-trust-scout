# NOVAIN TRUST — Agent error handling (enterprise contract)

## Envelope (always)

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "API rate limit exceeded.",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

Branch on **`error.code`**, never on `message` text.

Live catalog: `GET /api/public/v1/errors`

## Codes

| Code | HTTP | Retryable | Agent action |
|------|------|-----------|--------------|
| UNAUTHORIZED | 401 | no | Fix credentials |
| KEY_REVOKED | 403 | no | Stop; new key required |
| KEY_EXPIRED | 403 | no | Stop; renew key |
| FORBIDDEN | 403 | no | Stop; permission/environment |
| RATE_LIMITED | 429 | yes | Wait `Retry-After` or `X-RateLimit-Reset` |
| TARGET_BLOCKED | 422 | no | Do not treat URL as safe |
| INVALID_TARGET | 400 | no | Fix URL |
| INVALID_REQUEST | 400 | no | Fix body vs OpenAPI |
| NOT_FOUND | 404 | no | Bad verification id |
| INTERNAL_ERROR | 500 | yes | Backoff then fail closed |
| SERVICE_UNAVAILABLE | 503 | yes | Backoff |

## Rate limit headers

On success and on 429:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset` (unix timestamp)
- `Retry-After` (seconds, on 429)

## HTTP 200 is not always “safe”

A successful verify can still mean **do not proceed**:

- Read `recommendation`
- Read `risk_gates`
- Read `unknowns`
- Read `evidence[]`

Example: public URL redirects to private → HTTP 200, `redirect_safe=fail`, critical gate, `do_not_proceed`.

## Batch

`POST /verify/website/batch` returns **HTTP 200** with per-item results:

```json
{
  "results": [
    {"target": "https://a.com", "ok": true, "result": { ... }},
    {"target": "http://127.0.0.1/", "ok": false, "error": {"code": "TARGET_BLOCKED", "message": "..."}}
  ]
}
```

Inspect **each** `results[i].ok` / `results[i].error`.

## Pseudocode

```
resp = POST verify
if resp.status == 429:
    sleep(Retry-After); retry
if resp.status in (401, 403):
    abort credentials
if resp.status == 422 and code == TARGET_BLOCKED:
    refuse action on that URL
if resp.status >= 500:
    backoff; fail closed if persistent
if resp.status == 200:
    if recommendation == do_not_proceed: refuse
    if recommendation == review_required: escalate
    if recommendation == proceed_with_caution: limited action
    if recommendation == proceed: continue
```
