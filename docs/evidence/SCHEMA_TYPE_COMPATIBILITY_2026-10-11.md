# Schema type compatibility continuation — 2026-10-11

APIShield previously compared types only when both schemas contained unequal string type declarations. A newly constrained request or an unconstrained response could return no finding, and JSON Schema type arrays were silently ignored. Integer-to-number widening was also treated the same in both request and response directions.

The comparison now uses disjoint JSON instance groups, including the integer subset of number. Absent type accepts all groups; string and array declarations are validated against the seven permitted JSON Schema type names. Arrays must be nonempty and contain unique strings. Malformed declarations raise CONTRACT_SCHEMA_TYPE_INVALID. Inputs losing accepted type groups and outputs gaining possible type groups retain the existing SCHEMA_TYPE_CHANGED rule family, with BREAKING severity and LIMITED coverage. Interacting enum/const/other constraints can make a type restriction redundant; this is not a complete schema-inclusion proof.

The OpenAPI 3.0 nullable keyword remains explicitly REVIEW/UNSUPPORTED; this continuation supports JSON Schema type-set forms and does not claim complete cross-dialect nullability semantics.

Verification: 36 new regression cases include independent Draft202012Validator counterexamples, missing type constraints, nullable type unions, integer/fractional/boolean distinctions, semantically equivalent arrays and safe reverse directions, malformed declarations and nested escaped pointers. The unmodified main source reproduced **24 failures / 12 passes**. Patched source passed all **36** new cases. The combined request/response/enum/nested compatibility corpus passed **102** tests with Python warnings treated as errors. Full exact-commit GitHub application/PostgreSQL/contract/sandbox CI is required before merge; this local receipt does not assert those results yet.

Specification reference: https://json-schema.org/draft/2020-12/json-schema-validation#name-type

No staging deployment, access grant or production acceptance is performed by this change. The release approval block, positive authenticated business acceptance, external integrations, load and recovery gates remain open.
