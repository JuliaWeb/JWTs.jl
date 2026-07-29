const VerifierKeySource = Union{JWKSet,RemoteJWKSet,OIDCDiscovery}

struct Verifier
    keyset::VerifierKeySource
    algorithms::Vector{String}
    issuer::Union{Nothing,String}
    audiences::Union{Nothing,Vector{String}}
    subject::Union{Nothing,String}
    jwtid::Union{Nothing,String}
    nonce::Union{Nothing,String}
    leeway::Float64
    max_age::Union{Nothing,Float64}
    required_claims::Vector{String}
    now::Function
end

struct VerifiedJWT
    token::JWT
    header::JWTJSONDict
    claims::JWTJSONDict
    kid::String
    alg::String
    key::JWK
end

claims(jwt::VerifiedJWT) = jwt.claims
kid(jwt::VerifiedJWT) = jwt.kid
alg(jwt::VerifiedJWT) = jwt.alg

normalize_expected_audiences(::Nothing) = nothing
normalize_expected_audiences(aud::AbstractString) = String[String(aud)]
normalize_expected_audiences(auds) = String[String(aud) for aud in auds]

function normalize_required_claims(required_claims)
    out = String[]
    for claim in required_claims
        claim_s = String(claim)
        claim_s in out || push!(out, claim_s)
    end
    return out
end

"""
    Verifier(keyset; algorithms, issuer=nothing, audience=nothing, subject=nothing,
             jwtid=nothing, nonce=nothing, leeway=0, max_age=nothing,
             required_claims=String[], now=time)
    Verifier(issuer_url; algorithms, ..., now=time, cache_now=<monotonic clock>)
    Verifier(; jwks_uri, algorithms, ..., now=time, cache_now=<monotonic clock>)

Verification policy for [`verify`](@ref). `keyset` is a [`JWKSet`](@ref) or a vector
of keys. Use an issuer URL for OpenID Connect discovery, or use the `jwks_uri`
keyword for a remote key set.

`algorithms` is mandatory and must be non-empty: accepting whatever algorithm a token
asks for is how algorithm-substitution attacks start, so the caller states which ones
are acceptable up front.

`issuer`, `audience`, `subject`, `jwtid`, and `nonce` are checked only when supplied.
`leeway` (seconds) absorbs clock skew on the time claims, and `max_age` bounds how old
`iat` may be.

!!! note "Time claims are enforced only when present"
    `exp` and `nbf` are validated when the token carries them, but a token with no `exp`
    at all is *not* rejected — it simply never expires. If your issuer is supposed to
    always set an expiry, say so explicitly:

    ```julia
    Verifier(keyset; algorithms=["RS256"], required_claims=["exp"])
    ```

Convenience constructors also accept an OIDC issuer URL (`Verifier(issuer_url; ...)`) or
a `jwks_uri` keyword, both of which fetch and cache the key set for you. Cache durations
use the monotonic `cache_now` clock by default. The `now` clock supplies epoch seconds
for JWT NumericDate claims.
"""
function Verifier(
    keyset::VerifierKeySource;
    algorithms=nothing,
    issuer::Union{Nothing,AbstractString}=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
    now=time,
)
    algorithms === nothing && throw(ArgumentError("Verifier requires an explicit algorithms allowlist"))
    algs = String[String(alg) for alg in algorithms]
    isempty(algs) && throw(ArgumentError("Verifier requires a non-empty algorithms allowlist"))
    for alg in algs
        alg in SUPPORTED_ALGORITHMS || throw(ArgumentError("unsupported verification algorithm: $alg"))
    end
    leeway_s = normalize_nonnegative_seconds("leeway", leeway)
    max_age_s = max_age === nothing ? nothing :
        normalize_nonnegative_seconds("max_age", max_age)
    return Verifier(
        keyset,
        algs,
        issuer === nothing ? nothing : String(issuer),
        normalize_expected_audiences(audience),
        subject === nothing ? nothing : String(subject),
        jwtid === nothing ? nothing : String(jwtid),
        nonce === nothing ? nothing : String(nonce),
        leeway_s,
        max_age_s,
        normalize_required_claims(required_claims),
        normalize_now_function(now),
    )
end

Verifier(keys::Vector; kwargs...) = Verifier(JWKSet(keys); kwargs...)

function Verifier(
    issuer_url::AbstractString;
    discovery_path::AbstractString="/.well-known/openid-configuration",
    metadata_ttl::Real=300,
    jwks_ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher=nothing,
    downloader=nothing,
    now=time,
    cache_now=monotonic_seconds,
    algorithms=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
)
    issuer_s = String(issuer_url)
    source = OIDCDiscovery(
        issuer_s;
        discovery_path=discovery_path,
        metadata_ttl=metadata_ttl,
        jwks_ttl=jwks_ttl,
        refresh_cooldown=refresh_cooldown,
        default_algs=default_algs,
        fetcher=fetcher,
        downloader=downloader,
        now=cache_now,
    )
    return Verifier(
        source;
        algorithms=algorithms,
        issuer=issuer_s,
        audience=audience,
        subject=subject,
        jwtid=jwtid,
        nonce=nonce,
        leeway=leeway,
        max_age=max_age,
        required_claims=required_claims,
        now=now,
    )
end

function Verifier(;
    jwks_uri=nothing,
    jwks_ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher=nothing,
    downloader=nothing,
    now=time,
    cache_now=monotonic_seconds,
    algorithms=nothing,
    issuer::Union{Nothing,AbstractString}=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
)
    jwks_uri === nothing && throw(ArgumentError("Verifier requires a JWKSet, key vector, OIDC issuer, or jwks_uri"))
    source = RemoteJWKSet(
        jwks_uri;
        ttl=jwks_ttl,
        refresh_cooldown=refresh_cooldown,
        default_algs=default_algs,
        fetcher=fetcher,
        downloader=downloader,
        now=cache_now,
    )
    return Verifier(
        source;
        algorithms=algorithms,
        issuer=issuer,
        audience=audience,
        subject=subject,
        jwtid=jwtid,
        nonce=nonce,
        leeway=leeway,
        max_age=max_age,
        required_claims=required_claims,
        now=now,
    )
end

function claim_number(claimset, name::String)
    value = get(claimset, name, nothing)
    value isa Bool && throw(JWTClaimError(:claim_type, "jwt claim $name must be numeric"))
    if value isa Real
        number = Float64(value)
        isfinite(number) ||
            throw(JWTClaimError(:claim_type, "jwt claim $name must be finite"))
        return number
    end
    throw(JWTClaimError(:claim_type, "jwt claim $name must be numeric"))
end

function claim_string(claimset, name::String)
    haskey(claimset, name) || throw(JWTClaimError(:claim_missing, "jwt missing required claim $name"))
    value = claimset[name]
    value isa AbstractString && return String(value)
    throw(JWTClaimError(:claim_type, "jwt claim $name must be a string"))
end

function claim_audiences(claimset)
    haskey(claimset, "aud") || throw(JWTClaimError(:claim_missing, "jwt missing required claim aud"))
    value = claimset["aud"]
    value isa AbstractString && return String[String(value)]
    if value isa AbstractVector
        audiences = String[]
        for aud in value
            aud isa AbstractString || throw(JWTClaimError(:claim_type, "jwt claim aud entries must be strings"))
            push!(audiences, String(aud))
        end
        return audiences
    end
    throw(JWTClaimError(:claim_type, "jwt claim aud must be a string or array of strings"))
end

function require_claims!(claimset, required_claims)
    for claim in required_claims
        haskey(claimset, claim) || throw(JWTClaimError(:claim_missing, "jwt missing required claim $claim"))
    end
    return nothing
end

"""
    check_time_claims(claimset; now=time(), leeway=0)

Enforce the `exp` and `nbf` claims of a decoded claim set, throwing [`JWTClaimError`](@ref)
when the token is expired or not yet valid. Claims that are absent are not enforced.

This is the shared core used by both [`verify`](@ref) and [`with_valid_jwt`](@ref).
"""
function check_time_claims(claimset; now::Real=time(), leeway::Real=0)
    now_s = Float64(now)
    isfinite(now_s) || throw(ArgumentError("now must be finite"))
    leeway_s = normalize_nonnegative_seconds("leeway", leeway)
    if haskey(claimset, "exp")
        exp = claim_number(claimset, "exp")
        now_s < exp + leeway_s || throw(JWTClaimError(:token_expired, "jwt expired"))
    end
    if haskey(claimset, "nbf")
        nbf = claim_number(claimset, "nbf")
        now_s + leeway_s >= nbf || throw(JWTClaimError(:token_not_yet_valid, "jwt not yet valid"))
    end
    return nothing
end

function validate_time_claims!(claimset, verifier::Verifier, now_value::Real)
    now_s = Float64(now_value)
    leeway = verifier.leeway
    check_time_claims(claimset; now=now_s, leeway=leeway)
    if haskey(claimset, "iat")
        iat = claim_number(claimset, "iat")
        now_s + leeway >= iat || throw(JWTClaimError(:token_issued_in_future, "jwt issued in the future"))
        if verifier.max_age !== nothing
            # `leeway` widens the max_age window, consistent with how it relaxes exp/nbf:
            # it absorbs clock skew on `iat` rather than tightening the freshness bound.
            now_s - iat <= verifier.max_age + leeway || throw(JWTClaimError(:token_too_old, "jwt is older than max_age"))
        end
    elseif verifier.max_age !== nothing
        throw(JWTClaimError(:claim_missing, "jwt missing required claim iat"))
    end
    return nothing
end

function validate_expected_claims!(claimset, verifier::Verifier)
    verifier.issuer === nothing || claim_string(claimset, "iss") == verifier.issuer || throw(JWTClaimError(:claim_mismatch, "jwt issuer mismatch"))
    verifier.subject === nothing || claim_string(claimset, "sub") == verifier.subject || throw(JWTClaimError(:claim_mismatch, "jwt subject mismatch"))
    verifier.jwtid === nothing || claim_string(claimset, "jti") == verifier.jwtid || throw(JWTClaimError(:claim_mismatch, "jwt id mismatch"))
    verifier.nonce === nothing || claim_string(claimset, "nonce") == verifier.nonce || throw(JWTClaimError(:claim_mismatch, "jwt nonce mismatch"))
    if verifier.audiences !== nothing
        actual = claim_audiences(claimset)
        any(aud -> aud in verifier.audiences, actual) || throw(JWTClaimError(:claim_mismatch, "jwt audience mismatch"))
    end
    return nothing
end

function validate_claims!(claimset, verifier::Verifier, now_value::Real)
    require_claims!(claimset, verifier.required_claims)
    validate_time_claims!(claimset, verifier, now_value)
    validate_expected_claims!(claimset, verifier)
    return nothing
end

"""
    verify(verifier::Verifier, jwt) -> VerifiedJWT

Fully verify a JWT: decode the header, check `alg` against the verifier's allowlist,
resolve the signing key, verify the signature, then validate the claims. `jwt` may be a
compact token `String` or a [`JWT`](@ref).

Returns a [`VerifiedJWT`](@ref) on success. On failure it throws a [`JWTError`](@ref) —
[`JWTVerificationError`](@ref) for header/signature problems, [`JWTClaimError`](@ref) for
claim problems — each carrying a `code` symbol such as `:algorithm_disallowed`,
`:signature_invalid`, `:token_expired`, or `:claim_mismatch`.

Unlike [`validate!`](@ref), which only checks the signature, this enforces the claim
policy configured on the `Verifier`.

The `kid` header is optional: when the token omits it and the key set holds exactly one
key, that key is used (RFC 7515 §4.1.4). An ambiguous key set requires the token to say
which key it used.
"""
verify(verifier::Verifier, jwt::String) = verify(verifier, JWT(jwt))

function verify(verifier::Verifier, jwt::JWT)
    issigned(jwt) || throw(JWTVerificationError(:token_unsigned, "jwt is not signed"))
    header = try
        decode_jwt_json_object(jwt.header)
    catch err
        err isa JWTError && rethrow()
        throw(JWTVerificationError(:malformed_header, "jwt header is not valid base64url-encoded JSON"))
    end
    validate_claims_protected_header(header)
    header_alg = jwt_string_claim(header, "alg")
    header_alg === nothing && throw(JWTVerificationError(:algorithm_missing, "jwt header does not include alg"))
    header_alg in verifier.algorithms || throw(JWTVerificationError(:algorithm_disallowed, "jwt algorithm is not allowed"))
    header_kid = if haskey(header, "kid")
        value = header["kid"]
        value isa AbstractString || throw(JWTVerificationError(
            :key_id_invalid,
            "jwt kid header parameter must be a string"))
        String(value)
    else
        nothing
    end

    resolved_kid, key, generation = if header_kid === nothing
        resolve_sole_verification_key_with_generation(verifier.keyset)
    else
        resolved_key, resolved_generation =
            resolve_verification_key_with_generation(verifier.keyset, header_kid)
        header_kid, resolved_key, resolved_generation
    end

    valid = validate!(jwt, key; algorithms=verifier.algorithms)
    if !valid && refresh_for_key_miss!(
            verifier.keyset;
            observed_generation=generation,
        )
        resolved_kid, key, _ = if header_kid === nothing
            resolve_sole_verification_key_with_generation(verifier.keyset)
        else
            resolved_key, resolved_generation =
                resolve_verification_key_with_generation(verifier.keyset, header_kid)
            header_kid, resolved_key, resolved_generation
        end
        valid = validate!(jwt, key; algorithms=verifier.algorithms)
    end
    valid || throw(JWTVerificationError(:signature_invalid, "invalid jwt signature"))
    claimset = try
        decode_jwt_json_object(jwt.payload)
    catch err
        err isa JWTError && rethrow()
        throw(JWTClaimError(:malformed_payload, "jwt payload is not valid base64url-encoded JSON"))
    end
    validate_claims!(claimset, verifier, verifier.now())
    return VerifiedJWT(jwt, header, claimset, resolved_kid, header_alg, key)
end
