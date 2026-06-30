# JWTs

[![Build Status](https://github.com/JuliaWeb/JWTs.jl/workflows/CI/badge.svg)](https://github.com/JuliaWeb/JWTs.jl/actions?query=workflow%3ACI+branch%3Amaster)
[![codecov](https://codecov.io/gh/JuliaWeb/JWTs.jl/branch/master/graph/badge.svg?token=VK7JZ2hMQx)](https://codecov.io/gh/JuliaWeb/JWTs.jl)

JWTs.jl signs and verifies JSON Web Tokens (JWTs) and JSON Web Keys (JWKs). It supports local key sets, cached remote JWKS endpoints, and OpenID Connect discovery without requiring HTTP.jl.

JWTs.jl intentionally exports no names. Use the `JWTs.` namespace, or explicitly import the names you want. On Julia versions that support `public`, documented APIs are marked public without being exported.

## Installation

```julia
import Pkg
Pkg.add("JWTs")
```

JWTs.jl supports Julia 1.6 and newer.

## Supported Algorithms

JWTs.jl supports these JOSE signing algorithms:

- HMAC: `HS256`, `HS384`, `HS512`
- RSA PKCS#1 v1.5: `RS256`, `RS384`, `RS512`
- RSA-PSS: `PS256`, `PS384`, `PS512`
- ECDSA: `ES256`, `ES384`, `ES512`
- EdDSA: `EdDSA` with Ed25519 keys

Asymmetric crypto uses OpenSSL through OpenSSL_jll. HMAC uses SHA.jl.

## Keys

`JWTs.JWKSet` stores keys by `kid`. It can be created from a JWKS URL, a `file://` URL, or an in-memory vector of parsed JWK dictionaries. JWKS parsing supports public RSA, EC, OKP/Ed25519, and symmetric HMAC keys.

```julia
using JWTs

keyset = JWTs.JWKSet("https://issuer.example/oauth2/default/keys")
JWTs.refresh!(keyset)

key = keyset.keys["signing-key-id"]
JWTs.alg(key)
```

Private PEM keys can be loaded with `JWTs.parse_keyfile`. RSA, EC, and Ed25519 private keys are supported for signing.

```julia
private_key = JWTs.parse_keyfile("/secure/path/rs256.private.pem")
signing_key = JWTs.JWKRSA("RS256", private_key)
```

For EC and OKP keys, use the namespaced constructors:

```julia
ec_key = JWTs.JWKEC("ES256", JWTs.parse_keyfile("/secure/path/es256.private.pem"), "P-256")
okp_key = JWTs.JWKOKP("EdDSA", JWTs.parse_keyfile("/secure/path/ed25519.private.pem"), "Ed25519")
```

## Signing

Create a token from a claims dictionary, then sign it with a key and `kid`.

```julia
payload = Dict(
    "iss" => "https://issuer.example/oauth2/default",
    "sub" => "user-123",
    "aud" => "api://default",
    "iat" => floor(Int, time()),
    "exp" => floor(Int, time()) + 300,
)

jwt = JWTs.JWT(; payload=payload)
JWTs.sign!(jwt, signing_key, "signing-key-id")
string(jwt)
```

You can also sign from a key set:

```julia
JWTs.sign!(jwt, signing_keyset, "signing-key-id")
```

## Token Representation

`JWTs.JWT` stores the compact JWT parts in encoded form. `jwt.payload`, `jwt.header`, and `jwt.signature` correspond to the base64url-encoded compact token segments. `jwt.header` and `jwt.signature` are `nothing` until the token is signed or parsed from a signed compact JWT string.

`JWTs.claims(jwt)` decodes and parses the payload JSON with JSON.jl. `JWTs.kid(jwt)` and `JWTs.alg(jwt)` read the decoded header values from a signed token.

For compatibility with older code, direct assignment to `jwt.payload`, `jwt.header`, and `jwt.signature` is accepted for encoded compact token parts. Any such assignment clears the cached validation state. `jwt.verified` and `jwt.valid` are read-only; call `JWTs.sign!`, `JWTs.validate!`, or `JWTs.verify` to update validation state.

## Verification With Claims

For applications, prefer `JWTs.Verifier` over calling `validate!` directly. A verifier checks the signature, enforces an explicit algorithm allowlist, validates registered claims, and returns a `JWTs.VerifiedJWT` only after all checks pass.

```julia
verifier = JWTs.Verifier(
    keyset;
    algorithms=["RS256"],
    issuer="https://issuer.example/oauth2/default",
    audience="api://default",
    leeway=60,
    required_claims=["exp", "iat"],
)

verified = JWTs.verify(verifier, token_string)
claims = JWTs.claims(verified)
claims["sub"]
```

Supported verifier options include:

- `algorithms`: required explicit allowlist such as `["RS256"]`
- `issuer`: expected `iss`
- `audience`: expected `aud`, as a string or list of accepted audiences
- `subject`: expected `sub`
- `jwtid`: expected `jti`
- `nonce`: expected `nonce`
- `leeway`: clock skew allowance in seconds
- `max_age`: maximum token age from `iat`
- `required_claims`: claims that must be present
- `now`: injectable clock, useful for deterministic tests

`aud` may be either a string or an array of strings, matching RFC 7519.

`JWTs.VerifiedJWT` exposes the original parsed token as `verified.token`, the decoded header as `verified.header`, the decoded claims as `verified.claims`, and the matched verification key as `verified.key`. The convenience accessors `JWTs.claims(verified)`, `JWTs.kid(verified)`, and `JWTs.alg(verified)` are also available.

## Remote JWKS

For a provider JWKS endpoint, construct a verifier with `jwks_uri`. Keys are fetched lazily, cached for `jwks_ttl` seconds, refreshed when stale, and refreshed early when a token contains an unknown `kid`.

```julia
verifier = JWTs.Verifier(;
    jwks_uri="https://issuer.example/oauth2/default/keys",
    algorithms=["RS256"],
    issuer="https://issuer.example/oauth2/default",
    audience="api://default",
    jwks_ttl=300,
    refresh_cooldown=30,
)

verified = JWTs.verify(verifier, token_string)
```

`refresh_cooldown` prevents repeated failed refresh attempts from turning every bad token into a network request. The last good key set is retained when a later refresh fails.

Tests can inject a deterministic fetcher:

```julia
fetcher = url -> read("fixtures/jwks.json", String)
verifier = JWTs.Verifier(; jwks_uri="https://issuer.example/keys", algorithms=["RS256"], fetcher=fetcher)
```

The default fetcher uses Downloads.jl. Pass `downloader=Downloads.Downloader()` when you want to reuse a configured Downloads downloader, or pass `fetcher=url -> ...` when tests or applications need full control over network access.

## OpenID Connect Discovery

Pass an issuer URL as the first argument to use OpenID Connect discovery. JWTs.jl fetches `/.well-known/openid-configuration`, validates a matching discovery `issuer` when present, reads `jwks_uri`, and then uses the same cached remote JWKS behavior.

```julia
verifier = JWTs.Verifier(
    "https://issuer.example/oauth2/default";
    algorithms=["RS256"],
    audience="api://default",
    metadata_ttl=300,
    jwks_ttl=300,
)

verified = JWTs.verify(verifier, token_string)
```

Use `discovery_path` if your provider uses a non-default discovery document path.

## Lower-Level Signature Validation

`JWTs.validate!` and `JWTs.with_valid_jwt` remain available as lower-level signature validation helpers. They do not validate registered claims such as `exp`, `nbf`, `iat`, `iss`, or `aud`.

```julia
jwt = JWTs.JWT(token_string)
JWTs.validate!(jwt, keyset, "signing-key-id"; algorithms=["RS256"])
```

Use these helpers when you intentionally want only signature validation. `algorithms` is optional for backwards compatibility, but passing an explicit allowlist is strongly recommended. Use `JWTs.Verifier` for application authentication and authorization boundaries.

## Errors

Verifier runtime failures throw subtypes of `JWTs.JWTError`:

- `JWTs.JWTVerificationError`: malformed, unsigned, disallowed-algorithm, or invalid-signature tokens
- `JWTs.JWTClaimError`: missing, malformed, expired, not-yet-valid, or mismatched claims
- `JWTs.JWKSError`: JWKS, OIDC discovery, fetch, parse, cooldown, or missing-key failures

Constructor option mistakes still throw `ArgumentError`.

```julia
try
    JWTs.verify(verifier, token_string)
catch err
    if err isa JWTs.JWTClaimError
        # token was signed but did not satisfy the configured claim policy
    elseif err isa JWTs.JWTVerificationError
        # token signature, header, or algorithm policy failed
    elseif err isa JWTs.JWKSError
        # key discovery or key lookup failed
    else
        rethrow()
    end
end
```

## Security Notes

- Always pass an explicit `algorithms` allowlist to `JWTs.Verifier`.
- Do not choose accepted algorithms from the untrusted token header.
- Prefer asymmetric algorithms such as `RS256`, `PS256`, `ES256`, or `EdDSA` for third-party issuer verification.
- Validate `iss` and `aud` for tokens accepted at service boundaries.
- Use `nonce` for ID-token replay protection when your protocol requires it.
- Keep key fetchers restricted to trusted issuer URLs.

## Migration Notes

JWTs.jl no longer depends on MbedTLS. Replace direct MbedTLS key parsing with `JWTs.parse_keyfile`.

```julia
# Old
# key = JWKRSA("RS256", MbedTLS.parse_keyfile("rs256.private.pem"))

# New
key = JWTs.JWKRSA("RS256", JWTs.parse_keyfile("rs256.private.pem"))
```

The high-level `JWTs.JWT`, `JWTs.JWKSet`, `JWTs.sign!`, `JWTs.validate!`, `JWTs.with_valid_jwt`, and `JWTs.claims` APIs remain available. `JWTs.validate!` still returns `true` or `false` and mutates `jwt.valid`; `JWTs.verify` throws typed JWT errors and returns a `JWTs.VerifiedJWT`.

JWTs.jl now requires Julia 1.6 or newer and uses OpenSSL_jll for asymmetric crypto. New application code should prefer `JWTs.Verifier` and `JWTs.verify` for end-to-end verification.
