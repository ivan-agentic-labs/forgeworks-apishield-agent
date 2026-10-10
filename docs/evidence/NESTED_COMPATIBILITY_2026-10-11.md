# Bounded nested compatibility continuation — 2026-10-11

Implemented operation/path parameter inheritance with exact source-list indices, nested properties and array item schema comparison, bounded local reference traversal, request constraint tightening, response constraint loosening, and request additional-property closure detection. Enum comparisons distinguish booleans from numbers, accept equivalent numeric values, and classify complex enums as unsupported review rather than crashing. Response enum expansion is breaking; removal remains a limited behavioral review.

Regression fixtures reproduce 13 previously failing cases and add 31 cases in total. Local command: `python -W error -m pytest tests --ignore=tests/e2e/test_ui_smoke.py -q`: 224 passed, 1 skipped (PostgreSQL integration). The mandatory browser flow and PostgreSQL proof remain delegated to exact-commit GitHub Actions; local Chromium download is unavailable.

Traversal is limited to 512 schema visits and depth 32 per schema surface. Cyclic/local unresolved references, complex enums, composition and dynamic references yield explicit unsupported review. This is a bounded syntactic contract classifier, not proof that every client is compatible. Type unions, read/write annotations, pattern interactions, boolean schemas and full JSON Schema implication are not fully supported. Referenced-path locations denote the dereferenced schema's logical use location; they are not an assertion that a `$ref` object contains the referenced fields inline.

Still open: TypeScript caller mapping and migration patches, isolated customer-code runner, live GitHub App permissions/webhook effects/draft PR flow, human-adjudicated compatibility corpus, provider quality/cost and full G1-E acceptance.
