# Security Audit (Repo) — 2025-12-15

Scope: workspace crates in this repository (Rust libraries, NEAR contracts, and the off-chain solver).

## Executive Summary

No critical RCE-class issues or hard-coded secrets were found in the repository during this pass. The highest-risk items are supply-chain/maintenance signals in transitive dependencies (unmaintained crates) and a small set of DoS-style robustness issues (panic-on-invalid-input / unbounded string decoding) which were fixed in this audit.

## What Was Run

- `cargo audit`
- `cargo deny check` (licenses/advisories/bans/sources)
- `cargo fmt --all -- --check`
- `cargo test` (core crates + contracts)
- `cargo clippy ... -- -W clippy::all`
- Repo-wide grep scans for common secret patterns (private keys, tokens) and for insecure patterns (`http://`, `ws://`, `danger_accept_invalid_*`, etc.)

## Changes Made During Audit

- Reduced GitHub Actions token blast radius:
  - Added explicit `permissions: contents: read`
  - Disabled credential persistence on `actions/checkout`
  - File: `.github/workflows/ci.yml`
- Added dependency policy config for repeatable supply-chain checks:
  - File: `deny.toml`
- Hardened cryptography helpers against DoS-by-invalid-input:
  - `mobilecoin-keys` no longer panics on invalid compressed points during shared secret computation.
  - File: `mobilecoin-keys/src/shared_secret.rs`
- Hardened NEAR contract signature decoding against oversized input:
  - Enforced authority signature hex length prior to decoding.
  - File: `poa-mobilecoin/contracts/mob-bridge/src/lib.rs`
- Added ed25519 signature edge-case tests for canonicality checks:
  - Tests for wrong pubkey length, non-canonical S values, boundary conditions
  - File: `poa-mobilecoin/contracts/mob-bridge/src/lib.rs`
- Documented simplified NEP-145 storage model in wmob-token:
  - Explicit documentation that overpayments are not refunded
  - File: `poa-mobilecoin/contracts/wmob-token/src/lib.rs`
- Removed duplicate `[profile.release]` stanzas from contract crates:
  - Files: `poa-mobilecoin/contracts/*/Cargo.toml`

## Findings (Prioritized)

### High (Address Soon)

1) Unmaintained transitive dependencies
- ~~`rustls-pemfile 1.0.4` via `reqwest 0.11.27` (`solver-mobilecoin`)~~ **FIXED**: Upgraded to reqwest 0.12
- `wee_alloc 0.4.5` via `near-sdk` (contracts / verifier)
- Impact: increased maintenance and incident-response risk; future vulnerabilities are more likely to land unpatched.
- Recommended:
  - ~~Upgrade `reqwest` to a version that no longer depends on `rustls-pemfile` (or that uses the replacement APIs).~~ **DONE**
  - Evaluate newer `near-sdk` versions and/or allocator configuration to avoid `wee_alloc` if possible.

### Medium

2) NEP-145 storage deposit handling in `wmob-token` is simplified
- `storage_deposit` doesn't track per-account deposits or refund overpayment (typical token contracts do), which can lead to user-fund loss or operator disputes.
- ~~Recommended: implement a standard NEP-145 storage ledger (or explicitly document the behavior as non-standard).~~ **ADDRESSED**: Added explicit documentation in code explaining the simplified model and its trade-offs.

3) Authority signature verification edge-cases (NEAR bridge)
- The bridge enforces a minimal "non-canonical S" check before calling `env::ed25519_verify`. This is likely fine, but canonicality rules are subtle and easy to get wrong over time.
- ~~Recommended: rely on the host verification alone unless you have a strong reason to add additional signature-format rules, and add test vectors for signature edge-cases.~~ **ADDRESSED**: Added comprehensive test vectors for ed25519 edge-cases including wrong pubkey length, non-canonical S values, and boundary conditions.

4) URL scheme hardening for the off-chain solver **FIXED**
- ~~Solver defaults are `wss://` / `https://`, but the config accepts arbitrary schemes (e.g., `ws://`), which enables easy MitM if misconfigured.~~
- ~~Recommended: validate schemes by default and allow insecure schemes only behind an explicit "dev mode" flag.~~ **DONE**: Added `ALLOW_INSECURE_URLS` flag, defaults to rejecting non-TLS URLs.

### Low / Hygiene

5) GitHub Actions supply-chain hardening
- Workflows use version tags (e.g. `actions/checkout@v4`) rather than pinning to commit SHAs.
- Recommended: pin critical actions to SHAs in high-security environments.

6) Reproducible profiles: duplicate `[profile.release]` stanzas **FIXED**
- ~~Contract crates define `profile.release` but Cargo ignores non-root package profiles; the effective settings come from the workspace root.~~
- ~~Recommended: remove the per-crate profile stanzas to avoid confusion.~~ **DONE**

## How To Re-run Locally

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -W clippy::all
cargo audit
cargo deny check all
```

