# Boolean schema compatibility regression — 2026-10-11

Baseline: 01be273deab05b45c8e45719b9e936f987fbcdb5.

The previous analyzer discarded false schema values through truthiness defaults and skipped unresolved parameter/response schemas. The new implementation preserves false, normalizes true to an unconstrained schema only in schema context, and reports unresolved schemas for review. Request narrowing to false and response widening from false are directional breaking findings. Exact root unconstrained/false comparisons are COVERED; object or nested interactions remain LIMITED. References retain the existing global review warning.

Independent Draft202012Validator witnesses cover request bodies, parameters, response schemas and nested array items. The new 29-case regression on the unchanged baseline produced 20 failures and 9 passes. The candidate plus existing type, enum, nested, extended and response compatibility suites passed 131 tests with warnings treated as errors.

Required full GitHub Actions checks: application CI, contract validation, PostgreSQL regressions and sandbox boundary checks. CI results must be inspected before merge. This evidence documents source-level verification; no Railway deployment or production acceptance is claimed.
