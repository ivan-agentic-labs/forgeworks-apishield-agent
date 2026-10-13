# Exact five-product staging release

`ops/releases/fleet-staging-candidate.json` records five reviewed source pins and runtime fingerprints. It is deployment intent, not proof of a running release or production acceptance.

The coordinated probe is `python scripts/verify_fleet_release.py`. It performs bounded, read-only requests to five fixed Railway staging origins. It requires healthy/readiness responses, an exact staging product/revision/fingerprint identity, and HTTP 401 for anonymous metrics and product business access. Any missing endpoint, stale release, changed fingerprint, unavailable service, or open anonymous boundary fails the entire fleet. Redirects, arbitrary target hosts, duplicate JSON keys and oversized responses are rejected. No credentials or customer records are read.

1. Review source CI at each candidate revision and the entire pending Railway patch.
2. Keep source pins and each `FORGEWORKS_RELEASE_SHA` identical. Retain the previous successful deployment and source for rollback.
3. Apply only the existing ForgeWorks staging environment; verify terminal `SUCCESS` for every service.
4. Run the manual **ForgeWorks Exact Five-Product Hosted Release Proof** workflow or local probe.
5. Record observed deployments and probe results. Continue authenticated tenant/product acceptance, workload latency, hosted recovery and independent production review separately.

The ordinary public readiness workflows can pass while old code is still live. They must not be used as proof that this candidate deployed. The exact fleet workflow intentionally runs manually after deployment; until the staged patch is applied it should fail.

Supabase and Railway SealAngel connections/resources are excluded. This probe does not establish a unified user-facing domain or portal, authenticated business results, private telemetry access, a latency SLO, hosted DR or production readiness.
