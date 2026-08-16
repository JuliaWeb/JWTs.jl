const VerifierKeySource = Union{JWKSet,RemoteJWKSet,OIDCDiscovery}

# Parametric on the key source and clock so a verifier built over a static
# keyset never makes the remote-JWKS refresh machinery statically reachable
# (and `now()` stays a direct call) — required for juliac --trim consumers.
# `C` is the type the payload is decoded into: `Dict{String,Any}` by default
# (an open claim set, read dynamically), or an application-declared claims
# struct passed as `Verifier(...; claims=MyClaims)`, decoded with
# `JSON.parse(payload, MyClaims)` so every claim read is a typed field access
# — the shape a statically compiled (`juliac --trim`) verifier needs.
struct Verifier{S<:VerifierKeySource, F, C}
    keyset::S
    algorithms::Vector{String}
    issuer::Union{Nothing,String}
    audiences::Union{Nothing,Vector{String}}
    subject::Union{Nothing,String}
    jwtid::Union{Nothing,String}
    nonce::Union{Nothing,String}
    leeway::Float64
    max_age::Union{Nothing,Float64}
    required_claims::Vector{String}
    now::F
    claims::Type{C}
end

"""
    JWTs.claimstype(verifier::Verifier) -> Type

The type a verifier decodes token payloads into (`Dict{String,Any}` by default).
"""
claimstype(::Verifier{S,F,C}) where {S,F,C} = C

struct VerifiedJWT{C}
    token::JWT
    header::JWTHeaderClaims
    claims::C
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

function Verifier(
    ::Type{C},
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
) where {C}
    isconcretetype(C) || throw(ArgumentError("Verifier claims type must be concrete, got $C"))
    algorithms === nothing && throw(ArgumentError("Verifier requires an explicit algorithms allowlist"))
    algs = String[String(alg) for alg in algorithms]
    isempty(algs) && throw(ArgumentError("Verifier requires a non-empty algorithms allowlist"))
    for alg in algs
        alg in SUPPORTED_ALGORITHMS || throw(ArgumentError("unsupported verification algorithm: $alg"))
    end
    leeway < 0 && throw(ArgumentError("leeway must be non-negative"))
    max_age !== nothing && max_age < 0 && throw(ArgumentError("max_age must be non-negative"))
    return Verifier(
        keyset,
        algs,
        issuer === nothing ? nothing : String(issuer),
        normalize_expected_audiences(audience),
        subject === nothing ? nothing : String(subject),
        jwtid === nothing ? nothing : String(jwtid),
        nonce === nothing ? nothing : String(nonce),
        Float64(leeway),
        max_age === nothing ? nothing : Float64(max_age),
        normalize_required_claims(required_claims),
        normalize_now_function(now),
        C,
    )
end

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
    claims::Type=Dict{String,Any},
)
    return Verifier(
        claims,
        keyset;
        algorithms,
        issuer,
        audience,
        subject,
        jwtid,
        nonce,
        leeway,
        max_age,
        required_claims,
        now,
    )
end


# Explicit forwarding (not `kwargs...` splatting) so the call resolves to
# the keyset constructor alone: with a splat, inference unions this over
# every keyword `Verifier` method, and the result type is no longer concrete.
Verifier(::Type{C}, keys::Vector; algorithms=nothing, issuer=nothing, audience=nothing, subject=nothing, jwtid=nothing, nonce=nothing, leeway::Real=0, max_age=nothing, required_claims=String[], now=time) where {C} =
    Verifier(C, JWKSet(keys); algorithms, issuer, audience, subject, jwtid, nonce, leeway, max_age, required_claims, now)

Verifier(keys::Vector; algorithms=nothing, issuer=nothing, audience=nothing, subject=nothing, jwtid=nothing, nonce=nothing, leeway::Real=0, max_age=nothing, required_claims=String[], now=time, claims::Type=Dict{String,Any}) =
    Verifier(claims, keys; algorithms, issuer, audience, subject, jwtid, nonce, leeway, max_age, required_claims, now)

function Verifier(
    ::Type{C},
    issuer_url::AbstractString;
    discovery_path::AbstractString="/.well-known/openid-configuration",
    metadata_ttl::Real=300,
    jwks_ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher=nothing,
    downloader=nothing,
    now=time,
    algorithms=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
) where {C}
    issuer_s = String(rstrip(String(issuer_url), '/'))
    source = OIDCDiscovery(
        issuer_s;
        discovery_path=discovery_path,
        metadata_ttl=metadata_ttl,
        jwks_ttl=jwks_ttl,
        refresh_cooldown=refresh_cooldown,
        default_algs=default_algs,
        fetcher=fetcher,
        downloader=downloader,
        now=now,
    )
    return Verifier(
        C,
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
    algorithms=nothing,
    issuer::Union{Nothing,AbstractString}=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
    claims::Type=Dict{String,Any},
)
    return Verifier(
        claims;
        jwks_uri,
        jwks_ttl,
        refresh_cooldown,
        default_algs,
        fetcher,
        downloader,
        now,
        algorithms,
        issuer,
        audience,
        subject,
        jwtid,
        nonce,
        leeway,
        max_age,
        required_claims,
    )
end

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
    algorithms=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
    claims::Type=Dict{String,Any},
)
    return Verifier(
        claims,
        issuer_url;
        discovery_path,
        metadata_ttl,
        jwks_ttl,
        refresh_cooldown,
        default_algs,
        fetcher,
        downloader,
        now,
        algorithms,
        audience,
        subject,
        jwtid,
        nonce,
        leeway,
        max_age,
        required_claims,
    )
end

function Verifier(
    ::Type{C};
    jwks_uri=nothing,
    jwks_ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher=nothing,
    downloader=nothing,
    now=time,
    algorithms=nothing,
    issuer::Union{Nothing,AbstractString}=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
) where {C}
    jwks_uri === nothing && throw(ArgumentError("Verifier requires a JWKSet, key vector, OIDC issuer, or jwks_uri"))
    source = RemoteJWKSet(
        jwks_uri;
        ttl=jwks_ttl,
        refresh_cooldown=refresh_cooldown,
        default_algs=default_algs,
        fetcher=fetcher,
        downloader=downloader,
        now=now,
    )
    return Verifier(
        C,
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
    value = claimvalue(claimset, name)
    value isa Bool && throw(JWTClaimError(:claim_type, "jwt claim $name must be numeric"))
    value isa Real && return Float64(value)
    throw(JWTClaimError(:claim_type, "jwt claim $name must be numeric"))
end

function claim_string(claimset, name::String)
    hasclaim(claimset, name) || throw(JWTClaimError(:claim_missing, "jwt missing required claim $name"))
    value = claimvalue(claimset, name)
    value isa AbstractString && return String(value)
    throw(JWTClaimError(:claim_type, "jwt claim $name must be a string"))
end

function claim_audiences(claimset)
    hasclaim(claimset, "aud") || throw(JWTClaimError(:claim_missing, "jwt missing required claim aud"))
    value = claimvalue(claimset, "aud")
    # JSON claims are concrete String / Vector{Any}; narrowing to those (not
    # AbstractString / AbstractVector) keeps the loop statically dispatched.
    value isa String && return String[value]
    if value isa Vector
        audiences = String[]
        for aud in value
            aud isa String || throw(JWTClaimError(:claim_type, "jwt claim aud entries must be strings"))
            push!(audiences, aud)
        end
        return audiences
    end
    value isa AbstractString && return String[String(value)]
    throw(JWTClaimError(:claim_type, "jwt claim aud must be a string or array of strings"))
end

# Read one claim from a decoded claim set: a dict lookup, or the field of an
# application-declared claims struct (`nothing` when absent / no such field).
# Everything below reads claims only through this seam and `hasclaim`, so a
# typed claim set flows through validation with concrete field types.
# Decode a payload into the verifier's claims type.
decode_claims(encoded::String, ::Type{Dict{String,Any}}) = decode_jwt_json_object(encoded)
decode_claims(encoded::String, ::Type{C}) where {C} = decodepart(encoded, C)

claimvalue(claims::AbstractDict, name::String) = get(claims, name, nothing)
@generated function claimvalue(claims::T, name::String) where {T}
    reads = [:(name == $(String(field)) && return getfield(claims, $(QuoteNode(field))))
             for field in fieldnames(T)]
    return Expr(:block, reads..., :(return nothing))
end
hasclaim(claims::AbstractDict, name::String) = haskey(claims, name)
hasclaim(claims::T, name::String) where {T} = claimvalue(claims, name) !== nothing

function require_claims!(claimset, required_claims)
    for claim in required_claims
        hasclaim(claimset, claim) || throw(JWTClaimError(:claim_missing, "jwt missing required claim $claim"))
    end
    return nothing
end

function validate_time_claims!(claimset, verifier::Verifier, now_value::Real)
    now_s = Float64(now_value)
    leeway = verifier.leeway
    if hasclaim(claimset, "exp")
        exp = claim_number(claimset, "exp")
        now_s <= exp + leeway || throw(JWTClaimError(:token_expired, "jwt expired"))
    end
    if hasclaim(claimset, "nbf")
        nbf = claim_number(claimset, "nbf")
        now_s + leeway >= nbf || throw(JWTClaimError(:token_not_yet_valid, "jwt not yet valid"))
    end
    if hasclaim(claimset, "iat")
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
    expected_audiences = verifier.audiences
    if expected_audiences !== nothing
        actual = claim_audiences(claimset)
        # capture the narrowed local, not the Union{Nothing,...} field
        any(aud -> aud in expected_audiences, actual) || throw(JWTClaimError(:claim_mismatch, "jwt audience mismatch"))
    end
    return nothing
end

function validate_claims!(claimset, verifier::Verifier, now_value::Real)
    require_claims!(claimset, verifier.required_claims)
    validate_time_claims!(claimset, verifier, now_value)
    validate_expected_claims!(claimset, verifier)
    return nothing
end

verify(verifier::Verifier, jwt::String) = verify(verifier, JWT(jwt))

function verify(verifier::Verifier, jwt::JWT)
    issigned(jwt) || throw(JWTVerificationError(:token_unsigned, "jwt is not signed"))
    header = try
        decode_jwt_header_claims(jwt.header)
    catch err
        err isa JWTError && rethrow()
        throw(JWTVerificationError(:malformed_header, "jwt header is not valid base64url-encoded JSON"))
    end
    header_alg = header.alg
    header_alg === nothing && throw(JWTVerificationError(:algorithm_missing, "jwt header does not include alg"))
    header_alg in verifier.algorithms || throw(JWTVerificationError(:algorithm_disallowed, "jwt algorithm is not allowed"))
    header_kid = header.kid
    header_kid === nothing && throw(JWTVerificationError(:key_id_missing, "jwt header does not include kid"))
    header.crit === nothing || throw(JWTVerificationError(
        :critical_header_unsupported,
        "jwt uses critical JOSE header parameters that this verifier does not support",
    ))
    header.b64 === nothing || throw(JWTVerificationError(
        :critical_header_unsupported,
        "jwt uses the unsupported JOSE b64 header parameter",
    ))
    key = resolve_verification_key(verifier.keyset, header_kid)
    valid = validate!(jwt, key; algorithms=verifier.algorithms)
    valid || throw(JWTVerificationError(:signature_invalid, "invalid jwt signature"))
    claimset = try
        decode_claims(jwt.payload, claimstype(verifier))
    catch err
        err isa JWTError && rethrow()
        throw(JWTClaimError(:malformed_payload, "jwt payload is not valid base64url-encoded JSON"))
    end
    validate_claims!(claimset, verifier, verifier.now())
    return VerifiedJWT(jwt, header, claimset, header_kid, header_alg, key)
end
