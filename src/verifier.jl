const VerifierKeySource = Union{JWKSet,RemoteJWKSet,OIDCDiscovery}

struct Verifier{S<:VerifierKeySource,N}
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
    now::N
end

struct VerifiedJWT{H<:AbstractDict{String},C<:AbstractDict{String},K<:JWK}
    token::JWT
    header::H
    claims::C
    kid::String
    alg::String
    key::K
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
    now::N=time,
) where {N}
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
        now,
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
    fetcher::F=nothing,
    downloader::D=nothing,
    now::N=time,
    algorithms=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
) where {F,D,N}
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
    fetcher::F=nothing,
    downloader::D=nothing,
    now::N=time,
    algorithms=nothing,
    issuer::Union{Nothing,AbstractString}=nothing,
    audience=nothing,
    subject::Union{Nothing,AbstractString}=nothing,
    jwtid::Union{Nothing,AbstractString}=nothing,
    nonce::Union{Nothing,AbstractString}=nothing,
    leeway::Real=0,
    max_age::Union{Nothing,Real}=nothing,
    required_claims=String[],
) where {F,D,N}
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
    value isa Int64 && return Float64(value)
    value isa Float64 && return value
    throw(JWTClaimError(:claim_type, "jwt claim $name must be numeric"))
end

function claim_string(claimset, name::String)
    value = get(claimset, name, nothing)
    value isa String && return value
    throw(JWTClaimError(:claim_type, "jwt claim $name must be a string"))
end

function claim_audiences(claimset)
    value = get(claimset, "aud", nothing)
    value isa String && return String[value]
    if value isa Vector{String}
        return copy(value)
    elseif value isa Vector{Any}
        audiences = String[]
        for aud in value
            aud isa String || throw(JWTClaimError(:claim_type, "jwt claim aud entries must be strings"))
            push!(audiences, aud)
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

function validate_time_claims!(claimset, verifier::Verifier, now_value::Real)
    now_s = Float64(now_value)
    leeway = verifier.leeway
    if haskey(claimset, "exp")
        exp = claim_number(claimset, "exp")
        now_s <= exp + leeway || throw(JWTClaimError(:token_expired, "jwt expired"))
    end
    if haskey(claimset, "nbf")
        nbf = claim_number(claimset, "nbf")
        now_s + leeway >= nbf || throw(JWTClaimError(:token_not_yet_valid, "jwt not yet valid"))
    end
    if haskey(claimset, "iat")
        iat = claim_number(claimset, "iat")
        now_s + leeway >= iat || throw(JWTClaimError(:token_issued_in_future, "jwt issued in the future"))
        if verifier.max_age !== nothing
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

verify(verifier::Verifier, jwt::String) = verify(verifier, JWT(jwt))

function verify(verifier::Verifier, jwt::JWT)
    issigned(jwt) || throw(JWTVerificationError(:token_unsigned, "jwt is not signed"))
    header = decode_jwt_json_object(jwt.header)
    header_alg = alg(jwt)
    header_alg === nothing && throw(JWTVerificationError(:algorithm_missing, "jwt header does not include alg"))
    header_alg in verifier.algorithms || throw(JWTVerificationError(:algorithm_disallowed, "jwt algorithm is not allowed"))
    header_kid = kid(jwt)
    header_kid === nothing && throw(JWTVerificationError(:key_id_missing, "jwt header does not include kid"))
    key = resolve_verification_key(verifier.keyset, header_kid)
    valid = validate!(jwt, key; algorithms=verifier.algorithms)
    valid || throw(JWTVerificationError(:signature_invalid, "invalid jwt signature"))
    claimset = decode_jwt_json_object(jwt.payload)
    validate_claims!(claimset, verifier, verifier.now())
    return VerifiedJWT(jwt, header, claimset, header_kid, header_alg, key)
end
