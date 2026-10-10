# Automatic API origin guard — 2026-10-10

The analysis console formerly accepted an arbitrary API base from URL parameters or saved browser state before the user acted. It now accepts automatic overrides only on the origin defined by the trusted deployment config. Foreign origins, non-HTTP schemes, credentials, query and fragment values are ignored. Same-origin path overrides remain supported. A different origin must be entered explicitly by the user; this guard is not a blanket restriction on manually configured integrations.

Eight new Node VM tests execute the actual console initialization with hostile and permitted values, including poisoned browser storage and trusted deployment overrides. No console API request is performed at initialization by app.js. Existing session concurrency tests also pass (11 total). CI runs all web test files. The real Chromium smoke test now checks both a hostile URL parameter and poisoned storage before its authorized API flow.

This fixes automatic destination selection; it does not protect against page XSS, compromised deployment scripts, malicious browser extensions, or deliberately entering an untrusted API origin. No identity-provider or production configuration was changed.
