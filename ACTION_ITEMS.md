# Action Items: Production-Grade JWTs.jl

## Context
- Repo: JWTs.jl
- Worktree: `/Users/jacob.quinn/Documents/Codex/2026-06-29/ok-s/work/JWTs.jl`
- Branch: `codex/production-grade-jwt-verifier`

## Target Outcome

Make JWTs.jl a production-grade, industry-standard JWT/JWS package while keeping the existing public names as non-breaking as practical. The final stack should remove MbedTLS, use OpenSSL_jll directly for asymmetric crypto, keep Downloads.jl for HTTP, add a provider-neutral verifier/result interface, cover common registered claim validation, support modern JOSE signing algorithms, document the new APIs, modernize CI, and open a PR with one focused commit per completed item.

## Items

### [x] ITEM-001 (P0) Add roadmap and branch scaffold
- Description: Capture the full implementation plan in-repo before changing behavior.
- Desired outcome: The worktree contains a clear action-item file with repo path, branch name, ordered work items, verification plans, assumptions, and completion criteria.
- Affected files: `ACTION_ITEMS.md`
- Implementation notes:
  - Add this file as the source of truth for the implementation sequence.
  - Commit only the roadmap/scaffold.
- Verification:
  - `git status --short`
  - `git diff --check`
- Assumptions:
  - The roadmap file is acceptable as a review artifact because the user explicitly asked for a full roadmap before implementation.
- Completion criteria:
  - Roadmap exists, is committed, and later items remain unchecked until their verification passes.
- Verification evidence:
  - `git diff --check` passed.
  - `git status --short` showed only `ACTION_ITEMS.md` before commit.

### [ ] ITEM-002 (P0) Make JWT parsing and validation state safe
- Description: The current mutable JWT stores stale `verified`/`valid` state, so a token can remain valid after payload mutation or after validation with different keys/algorithm policies.
- Desired outcome: JWT token data is immutable after construction, validation is policy-local and cannot be reused across keys or algorithm allowlists, malformed/missing headers fail predictably, and existing `isverified`/`isvalid` compatibility remains as non-breaking as practical.
- Affected files: `src/JWTs.jl`, `test/runtests.jl`
- Implementation notes:
  - Make JWT object parts immutable, or otherwise make mutation impossible from the public API.
  - Remove validation short-circuiting that is not keyed to the exact key and algorithm policy.
  - Ensure failed validation sets compatibility state consistently.
  - Make `kid(jwt)` and `alg(jwt)` return `nothing` when absent as documented.
  - Add regression tests for stale validation, changed algorithm allowlists, changed keys, missing `kid`, missing `alg`, malformed compact tokens, and `with_valid_jwt` failure shape.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - `git diff --check`
- Assumptions:
  - Making mutable fields immutable is acceptable under the user's stated compatibility preference.
  - Compatibility accessors can report the last attempted validation result, but validation itself must always recompute for the supplied policy.
- Completion criteria:
  - Existing signing/validation tests pass and new security regression tests fail on the old implementation but pass on the new implementation.

### [ ] ITEM-003 (P0) Replace MbedTLS with OpenSSL_jll-backed crypto
- Description: MbedTLS is the current crypto backend and should be removed because it is not the desired maintenance/security posture.
- Desired outcome: Project.toml no longer depends on MbedTLS; existing HS256/HS384/HS512 and RS256/RS384/RS512 signing and verification continue to work through SHA.jl and direct OpenSSL_jll libcrypto calls.
- Affected files: `Project.toml`, `src/JWTs.jl`, new crypto backend files under `src/`, `test/runtests.jl`, test key fixtures as needed.
- Implementation notes:
  - Add `OpenSSL_jll` and `SHA`.
  - Keep `JWKSymmetric`, `JWKRSA`, `JWK`, `JWKSet`, `sign!`, and `validate!` names.
  - Introduce key-loading helpers for PEM private/public keys to replace direct MbedTLS key usage.
  - Implement RSA JWK construction from `n`/`e` with OpenSSL EVP_PKEY.
  - Implement HMAC with SHA.jl and constant-time comparison.
  - Preserve Downloads.jl behavior for JWKS fetches.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test()'`
  - Search proof: `rg "MbedTLS" Project.toml src test README.md`
  - `git diff --check`
- Assumptions:
  - OpenSSL_jll v3 is acceptable as the direct backend.
  - Existing callers that constructed MbedTLS key objects will need to move to package-provided PEM helpers; type names and high-level flows remain.
- Completion criteria:
  - No package dependency or source dependency on MbedTLS remains, and existing RSA/HMAC behavior is covered by tests.

### [ ] ITEM-004 (P1) Add modern JOSE algorithm support
- Description: JWTs.jl only supports HS* and RS* today; industry-standard JWT libraries usually support PS*, ES*, and EdDSA as well.
- Desired outcome: Add verify/sign support for PS256/PS384/PS512, ES256/ES384/ES512, and EdDSA/Ed25519, including JWK parsing for RSA, EC, and OKP keys.
- Affected files: `src/JWTs.jl`, crypto backend files under `src/`, `test/runtests.jl`, new key fixtures under `test/keys/`
- Implementation notes:
  - Use OpenSSL EVP PSS params for PS*.
  - Convert ECDSA DER signatures to/from JOSE raw `R || S`.
  - Parse EC JWK `crv`, `x`, and `y`; parse OKP JWK `crv` and `x`.
  - Add PEM private key loading for RSA, EC, and Ed25519 signing tests.
  - Reject unsupported algorithms and key/algorithm mismatches explicitly.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - Cross-check generated tokens/signatures with OpenSSL CLI or independent vectors where practical.
  - `git diff --check`
- Assumptions:
  - `EdDSA` maps to Ed25519 initially; Ed448 can be evaluated separately if OpenSSL_jll support and test vectors are straightforward.
- Completion criteria:
  - All newly supported algorithms have positive, wrong-key, wrong-algorithm, tampered-signature, and malformed-key tests.

### [ ] ITEM-005 (P1) Add verifier options, verified result, and registered claim validation
- Description: JWTs.jl validates signatures but not standard JWT claims like `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, or `nonce`.
- Desired outcome: Add a provider-neutral verifier interface that returns a verified result object and validates common registered claims with explicit options and leeway.
- Affected files: `src/JWTs.jl`, possible new verifier files under `src/`, `test/runtests.jl`, `README.md`
- Implementation notes:
  - Add `Verifier`, `VerificationOptions`, or similarly named public types with narrow exports.
  - Add `VerifiedJWT` result carrying the parsed token, header, claims, key id, algorithm, and validation metadata.
  - Require explicit algorithm allowlists in the new interface.
  - Implement claim validation for `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, `nonce`, required claims, and clock leeway.
  - Handle `aud` as either string or array per RFC 7519.
  - Keep legacy `validate!`/`with_valid_jwt` as lower-level signature validation helpers.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - Tests for each claim success/failure path, leeway boundaries, missing required claims, wrong audience, and wrong issuer.
  - `git diff --check`
- Assumptions:
  - The new verifier interface can be added without making every legacy caller adopt it immediately.
- Completion criteria:
  - Tests demonstrate safe end-to-end verification with signature and claim validation, and invalid signatures cannot expose trusted claims through the new result API.

### [ ] ITEM-006 (P1) Add remote JWKS caching and OIDC discovery
- Description: Production JWT verification usually needs cached remote JWKS resolution and optional OpenID Connect discovery, similar to OktaJWTVerifier.jl but provider-neutral.
- Desired outcome: JWTs.jl can discover `jwks_uri`, cache JWKS with TTL/cooldown behavior, refresh on unknown `kid`, and verify tokens through the new verifier without provider-specific naming.
- Affected files: `src/JWTs.jl`, possible new provider/cache files under `src/`, `test/runtests.jl`, `README.md`
- Implementation notes:
  - Keep Downloads.jl as the HTTP layer.
  - Add injectable downloader/fetcher hooks for deterministic tests.
  - Parse OIDC discovery documents from `/.well-known/openid-configuration` without URL-joining bugs.
  - Add cache TTL, refresh-on-unknown-kid, and cooldown/error behavior.
  - Ensure concurrent verification cannot corrupt keyset state.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - Tests with in-memory fake discovery/JWKS fetchers for TTL, refresh, malformed JSON, HTTP failure, missing `jwks_uri`, unknown `kid`, and rotated keys.
  - `git diff --check`
- Assumptions:
  - No additional heavy HTTP dependency is needed.
- Completion criteria:
  - The provider-neutral verifier covers the useful OktaJWTVerifier.jl behavior without Okta-specific naming or assumptions.

### [ ] ITEM-007 (P2) Improve error taxonomy, docs, and migration guidance
- Description: Production users need clear errors, clear examples, and a migration path from old MbedTLS-backed key construction.
- Desired outcome: README documents signing, signature validation, verifier/claim validation, remote JWKS/OIDC verification, supported algorithms, security guidance, and MbedTLS migration notes.
- Affected files: `src/JWTs.jl`, `README.md`, possibly `docs/` if introduced
- Implementation notes:
  - Add small exception types or structured errors where they materially improve caller handling.
  - Document that algorithm allowlists must be caller-configured and not derived from untrusted tokens.
  - Show namespace-first examples and avoid broad new exports.
  - Include security notes aligned with RFC 8725.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - README examples manually checked or included as lightweight doctest-style snippets where feasible.
  - `git diff --check`
- Assumptions:
  - README-level documentation is enough unless the package already grows a docs site in a later maintainer pass.
- Completion criteria:
  - New API is discoverable and old-to-new migration is clear.

### [ ] ITEM-008 (P2) Modernize CI following JSON.jl patterns
- Description: CI currently uses older action versions and a Julia 1.3 matrix. The final PR should have modern, maintainable CI.
- Desired outcome: CI follows current Julia package patterns, tests meaningful Julia versions/platforms, caches appropriately, and avoids obsolete Codecov action setup.
- Affected files: `.github/workflows/ci.yml`, `.github/workflows/TagBot.yml`, `Project.toml`
- Implementation notes:
  - Inspect JSON.jl workflow patterns before editing.
  - Keep the Julia compat floor deliberate and justified by OpenSSL_jll/support needs.
  - Prefer current `julia-actions/setup-julia`, `julia-buildpkg`, `julia-runtest`, and coverage actions.
  - Include x64 Linux/macOS/Windows and a reasonable oldest-supported Julia version.
- Verification:
  - `julia --project=. --startup-file=no -e 'using Pkg; Pkg.test()'`
  - `git diff --check`
  - After PR opens: GitHub Actions checks are green.
- Assumptions:
  - Raising the Julia compat floor may be acceptable if required by OpenSSL_jll or maintained CI realities, but should be minimized and called out.
- Completion criteria:
  - Local tests pass and PR CI passes on all required jobs.

### [ ] ITEM-009 (P0) Open PR and watch CI to green
- Description: The user requested a PR with the complete stacked commit series and final CI review.
- Desired outcome: Push branch, open a human-readable PR without agent marker in the title, include `Co-authored by Codex` in the PR description, and watch CI until green or fix failures with additional focused commits.
- Affected files: GitHub PR state
- Implementation notes:
  - Ensure every prior item is committed before pushing.
  - Use a normal PR title.
  - Include a concise summary, security notes, compatibility notes, and test evidence.
  - Continue fixing CI failures until checks are green.
- Verification:
  - `git status --short --branch`
  - `gh pr view --web` or `gh pr view --json`
  - `gh pr checks --watch`
- Assumptions:
  - GitHub credentials are available for JuliaWeb/JWTs.jl or a fork workflow.
- Completion criteria:
  - PR exists, all intended commits are present, and CI is green.

## Compaction Continuity Block

```text
* Take investigation/review findings and make a detailed, prioritized action item .md file; ensure each action item has enough detail (description, affected files, etc.) that a fresh context/engineer "taking on" the item would understand what needs to be done and where to go to get started and ideally how to verify that it's done
* Start working on the action-item list, for each item:
  * Thoroughly investigate the action item and work involved, state assumptions, do the work, including verification step
  * Work until verification succeeds (i.e. tests pass)
  * Mark the item done in the action item list
  * Commit the work involved for this action item
  * Continue with the same steps on the next action item
* When compacting, the itemizer instructions should be preserved *exactly* to ensure continuity
* The action-item document should very clearly state the repo/worktree where the work should be done
* Post-compaction, if there are unstaged edits in files relating to the current action item, you should assume they were your own edits and should continue directly w/ work without pausing to confirm
* No shortcuts or cutting corners while doing the action item work; each item should be done thoughtfully, carefully, with production-quality effort/work put into it; we're not trying to rush the work here at all and prefer quality, robustness, and thoroughness over "quick wins".
* No backwards compat or unnecessary shims should be included unless specifically requested
```
