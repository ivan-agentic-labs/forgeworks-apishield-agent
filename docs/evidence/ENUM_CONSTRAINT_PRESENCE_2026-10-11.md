# Enum constraint presence regression — 2026-10-11

APIShield previously compared enum values only when both revisions supplied enum arrays. Adding an enum to a request body/query parameter or removing an enum from a response could therefore return no compatibility finding. A non-array enum could also be silently ignored.

The comparison now reports REQUEST_ENUM_CONSTRAINT_ADDED / REQUEST_PARAMETER_ENUM_CONSTRAINT_ADDED or RESPONSE_ENUM_CONSTRAINT_REMOVED as BREAKING with LIMITED coverage. These are conservative constraint-change findings: other assertions can make an enum redundant, and this comparison does not prove complete schema inclusion. Complex enum values require UNSUPPORTED review. A malformed non-array enum raises CONTRACT_ENUM_SHAPE_INVALID. Empty arrays are preserved as constraints rather than treated as absence.

The 18 new regression cases exercise string, boolean/numeric and null counterexamples, empty response enums, safe reverse directions, malformed values, complex enums, escaped nested-array pointers, deterministic findings and source-byte-bound evidence digests. JSON Schema Draft202012Validator independently verifies the sample instances admitted/rejected by each schema.

Validation: executing these tests against the unmodified main source reproduced **15 failures and 3 passes**. Applying the fix produced **18 passes**. The combined new and existing request/response/nested compatibility corpus produced **66 passes** with Python warnings treated as errors. Full application, PostgreSQL and contract CI results belong to the exact GitHub PR commit; this local receipt does not claim those have passed yet.

References consulted:
- https://json-schema.org/draft/2020-12/json-schema-validation#name-enum
- https://spec.openapis.org/oas/v3.1.0

This is a repository implementation fix, not a staging deployment or production acceptance. Railway staged release d7e9d350-5dae-4464-9869-e4103521ce0b remains blocked after the 2026-10-11 renewed deployment request returned “Cancelled — the user did not approve this action. No changes were made.” No alternate deployment path was attempted. Supabase readback still verifies forced RLS on all 62 product tables; the Auth leaked-password-protection warning remains open and cannot be changed through the available connector.
