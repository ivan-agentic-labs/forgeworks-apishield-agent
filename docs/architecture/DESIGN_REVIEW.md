# Current design review and source-of-truth (2026-10-13)

This page REPLACES the old bootstrap-era design-review prose. Read [revised product specification](../specifications/PRODUCT_SPECIFICATION_2026-10-13.md) and [unified application architecture](../platform/ONE_APP_FIVE_SERVICES.md) for the owner's target design.

**Separation of evidence:** the revised documents define desired behavior, not runtime proof. Implemented features must be verified against the commit, CI run, deployed image/source fingerprint and external integration environment. The production gate remains OPEN until evidence and signoff are recorded.

Older source and architecture details in Git history are historical. Do **not** delete or rewrite dated `docs/evidence/`, security controls, SQL migrations, contracts, or operational runbooks when updating design documents.
