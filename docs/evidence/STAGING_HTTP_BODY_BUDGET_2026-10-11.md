# 2026-10-11 staged HTTP request budget

## Exact code and acceptance boundary
- Release source SHA: `4cde5299461f9ae36113069a07446431b1ef7567`.
- Railway staging deployment: `684cf0e5-82b8-4040-8cfa-eb709f5176e9`, observed `SUCCESS` with one running, zero crashed replica at checkpoint.
- Request budget: 8 MiB actual/declared body; maximum 16,384 chunks; malformed/oversized Content-Length bounded; invalid requests return 400/413.
- Tests are synthetic TestClient/pure-ASGI, not measured external attack traffic or rate-limiting proof.
- Railway source is explicitly pinned to this SHA; documentation-only commits after it need not be deployed.

## Exact CI receipts
- APIShield Disposable Sandbox Proof: **success**, https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38087959585
- G1 Contract Verification: **success**, https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38087959610
- APIShield PostgreSQL Runtime Proof: **success**, https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38087959595
- APIShield MVP Application CI: **success**, https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38087959613

## Scope and remaining evidence
All listed CI checks were `success` for the pinned source. Staging deployment `SUCCESS` confirms startup/health gates according to Railway, not full product functionality. External `/readyz` and authenticated business workflow tests could not be independently completed from this execution environment; owner/tenant membership provisioning and all G3-G6 acceptance remain OPEN.
