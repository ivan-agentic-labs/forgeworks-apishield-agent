# TypeScript caller profile evidence — 2026-10-10

Added a pinned TypeScript AST analysis module and a bounded Python CLI that emits reviewable, hash-bound source migration proposals for the explicitly supported literal global-fetch/path-relocation profile.

Verification: 42 Node cases pass, covering actual AST locations, query preservation, multiple edit offsets, static HTTP method, shadowed/imported bindings, direct rebinding, source-as-data handling, comments/examples, unsupported forms, operation/global changes, duplicate identities, invalid paths/digests/syntax/budgets, strict JSON/UTF-8 and numeric precision. Five Python CLI cases pass; three independently use git apply to prove exact resulting bytes with missing final newline, LF and CRLF. Main CI has a mandatory dependency-install/Node-test/CLI-proof step; the early full Python tree skips only the CLI cases until that parser dependency is installed.

No user/customer source was executed. All fixtures are synthetic. Syntax and patch applicability are narrower than full project build or runtime service correctness. Worker/snapshot/approval/provider integration and live draft PR remain unfinished; see the architecture profile for the exact boundary.
