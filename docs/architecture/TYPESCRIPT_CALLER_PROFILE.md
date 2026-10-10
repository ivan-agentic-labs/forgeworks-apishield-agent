# TypeScript caller migration profile

`typescript-fetch-path-v1` is an offline, bounded profile for locating literal global `fetch` calls and proposing a source path migration. It uses the pinned TypeScript 5.9.3 compiler AST and declaration binding, not text replacement over comments/string examples. Input source is parsed as data: it is never imported, evaluated, emitted or executed, and no project module resolution or customer build script is performed.

## Input and use

Install the pinned parser dependency and send a JSON manifest on stdin:

```sh
npm ci --ignore-scripts --prefix packages/caller-analysis
python scripts/analyze_typescript_callers.py < caller-manifest.json > caller-proposal.json
```

The manifest has exactly `schema_version`, `base_sha`, `head_sha`, `before`, `after`, `sources`. Both revisions are full lowercase 40-character SHAs. `before` and `after` are OpenAPI 3.1 JSON objects; `sources` has 1–50 records with exactly `path`, `content`, `sha256`. Paths are relative ASCII `.ts` paths without traversal; `.tsx` and `.d.ts` are unsupported. Source SHA-256 must match the exact UTF-8 content. The CLI does not itself obtain source from GitHub, authenticate a repository, or prove that caller-declared revisions and content hashes belong to it. A provisioned source adapter must supply independently verified snapshots before this can become a product-integrated proposal.

Limits: manifest 4 MiB, each source 128 KiB, combined source 1 MiB, contracts 1 MiB each and 20,000 nodes/depth 32, total source AST 100,000 nodes. The fixed Node child has a 256 MiB heap limit and a 10-second parent deadline. Invalid UTF-8/Unicode, duplicate JSON keys, malformed syntax and invalid digests fail closed with a generic error that does not echo input. Numeric contract values are limited to safe integers; decimal/exponent input is rejected to avoid precision-collapsed comparisons.

## Supported migration

A removed static endpoint can map to exactly one new endpoint only when `operationId` is unique before and after, the method is unchanged, the operation object and path-level fields are unchanged, and all global fields except `info`/`paths` are unchanged. This profile never infers schema, server, method or business-policy changes. Template paths and changed operations remain review items. Info changes are metadata only for this profile.

The caller must be an unshadowed global `fetch` with a root-relative literal URL or a template literal without interpolation. Options must allow a statically known method; spreads, computed method names, duplicate methods, prototype-derived options and dynamic URLs are unsupported. Query text is preserved exactly. Imported/local/parameter-bound `fetch`, direct runtime rebinding, `globalThis.fetch` forms and unsupported URL shapes produce review findings without edits.

Declaration binding and literal method/path agreement are static evidence, not proof of runtime service ownership. External monkey-patching, indirect aliases, generated SDKs, axios clients, template URL binding, arbitrary inter-module behavior and calls absent from the supplied snapshot are outside this profile. Zero supported findings does not establish that no caller is affected.

## Evidence and gates

Results include source locations, operation identity, edits, exact before/after source hashes, patched content, applicable unified diff and its SHA-256. Contract hashes are hashes of canonical JSON objects, explicitly named `*_canonical_sha256`; they are not hashes of original YAML/file bytes. The CLI returns proposal data on stdout and writes no files.

Each proposal remains `sandbox_status: NOT_RUN` and `approval_status: PENDING`. Syntax is reparsed, but a real project lint/typecheck/build and contract suite have not run. Unified diffs include correct missing-final-newline markers. Tests independently apply the diff with `git apply` and verify the resulting source hash for no newline, LF and CRLF.

This module is not yet integrated into the durable worker, tenant snapshot tables, approval API or live GitHub App effect path. Those integrations and isolated customer-code execution remain unfinished. It grants no approval, makes no GitHub write, starts no provider workload and deploys nothing.

Reference: https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API (AST and in-memory compiler-host model; installed 5.9.3 APIs were also checked directly).
