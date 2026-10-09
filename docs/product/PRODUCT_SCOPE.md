# APIShield Agent — P0 Product Requirements & Scope

**Target buyer:** Lead backend/platform dan tim integrasi API.

**Measurable user promise:** Mengidentifikasi breaking change pada kontrak OpenAPI, mengaitkannya dengan pemanggil TypeScript yang terpengaruh, lalu menyiapkan patch yang hanya boleh menjadi draft PR setelah approval.

## P0 end-to-end workflow
Pilih installation dan repo yang diizinkan → pin kontrak sebelum/sesudah dengan SHA → semantic diff → cari caller → usulkan patch pada isolated runner → jalankan lint/build/contract test → tampilkan evidence → approval digest-pinned → draft PR.

## Included in P0
- OpenAPI 3.1.x input yang diparse dengan capability matrix eksplisit
- Repository GitHub dengan bahasa TypeScript dan struktur yang didukung
- Diff kontrak, dampak source, patch proposal, tests, approval, draft PR

## Explicitly out of scope
- Merge otomatis dan deployment pelanggan
- Eksekusi kode pelanggan di API server
- Dukungan semua bahasa dan seluruh ekstensi OpenAPI
- Akses semua repository organisasi secara default

## Roles & permission model
- `org_owner`: billing, org settings, members, quotas; does not automatically grant bypass to data policy.
- `org_admin`: invites within same tenant, configures allowed integrations, reviews impact.
- `editor`: creates runs/imports/draft analyses, cannot approve their own high-impact external write if separation-of-duty policy enables it.
- `reviewer`: approves signed revision/digest within policy and time window.
- `auditor`: read-only access to redacted audit + evidence.
- `service_worker`: machine identity with narrowly scoped effect grants, never unrestricted user impersonation; the BFF carries verified user access claims server-side.

## Product value and validation
Business hypothesis: targeted buyer experiences frequent repeatable failure that is expensive enough to justify adoption. Evidence needed: 3–5 structured buyer interviews, their current workaround, time/expense per incident, willingness to share consented/synthetic fixtures, and pilot pass criteria. These are **future prerequisites**, not interviews already done.

**North-star and guardrail metrics:** verified breaking-change recall on supported corpus, false positive rate of caller impact, patch build/contract-test pass rate, median analysis time and cost per run, remote writes with verified approval = 100%.

## P0 completion criteria
1. One authorized end-to-end job reaches its intended output with reproducible fixture and trace.
2. Duplicate requests / partial external timeout / revocation / cross-tenant access fail safely.
3. Every material output cites a source/digest/rule version and has a reviewer action where needed.
4. Evidence of output correctness must come from deterministic assertion and human review of edge cases; AI alone does not sign off.
5. Security, privacy, budget, and recovery gate conditions defined in governance are respected.

## Critical G1 assumptions pending
- Supported OpenAPI grammar and TS project layouts need corpus approval
- Remote isolated execution provider must be selected and security tested
- GitHub App permission manifest requires live validation

**Scope owner:** Founder/Product. **Security owner:** assigned reviewer. **Domain validator:** qualified buyer/SME. **Status:** PROVISIONAL, awaiting actual signed reviews.
