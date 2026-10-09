# APIShield Agent static viewer

This is a **vanilla HTML/CSS/JS blueprint UI**, not a production frontend or a BFF. It performs three authenticated, read-only requests when **Load analysis** is submitted:

- `GET /v1/analyses/{analysis_id}`
- `GET /v1/jobs/{job_id}`
- `GET /v1/analyses/{analysis_id}/findings?limit=100`

The API base URL is editable in the page and is persisted in browser local storage. It can also be supplied in the page URL (`?apiBaseUrl=http://127.0.0.1:8000`) or changed in `config.js`. The bearer token is only held in the form and is never written to the repository.

## Run locally

From the repository root, start the synthetic API in one terminal:

```bash
python -m pip install -e 'apps/api[test]'
APISHIELD_SEED_FIXTURE=1 APISHIELD_CORS_ORIGINS=http://127.0.0.1:8080,http://localhost:8080 \
  PYTHONPATH=apps/api/src uvicorn apishield_agent.main:app --reload --port 8000
```

In another terminal, serve this directory (a static server is required; opening the file directly is not supported):

```bash
python -m http.server 8080 --directory apps/web
```

Open <http://127.0.0.1:8080>, paste the development bearer token, and enter the `analysis_id` and `job_id` returned by the analysis-creation response. The UI shows loading, error, status, job, and finding states. GitHub writes and mutation endpoints are intentionally not exposed.

The local CORS allowlist is configurable through `APISHIELD_CORS_ORIGINS`; keep it limited to the static viewer origin during development. This viewer does not claim production readiness.
