using JWTs

const TRIM_KID = "trim-hs256"
const TRIM_ISSUER = "https://issuer.example"
const TRIM_DISCOVERY_URL = TRIM_ISSUER * "/.well-known/openid-configuration"
const TRIM_JWKS_URI = TRIM_ISSUER * "/jwks"
const TRIM_AUDIENCE = "api://trim"
const TRIM_SUBJECT = "trim-subject"
const TRIM_JWT_ID = "trim-jti"
const TRIM_NONCE = "trim-nonce"
const TrimClaimValue = Union{Int64,String,Vector{String}}

trim_now()::Float64 = 1_500.0
trim_secret()::Vector{UInt8} = collect(codeunits("trim-compile-secret-material"))

function trim_oct_jwk()
    return Dict(
        "kid" => TRIM_KID,
        "kty" => "oct",
        "alg" => "HS256",
        "k" => JWTs.base64url_encode(trim_secret()),
    )
end

function trim_fetch(url::String)
    if url == TRIM_DISCOVERY_URL
        return Dict("issuer" => TRIM_ISSUER, "jwks_uri" => TRIM_JWKS_URI)
    elseif url == TRIM_JWKS_URI
        return Dict("keys" => [trim_oct_jwk()])
    end
    error("unexpected trim fetch URL: $url")
end

function trim_keyset()::JWTs.JWKSet
    keyset = JWTs.JWKSet("")
    keyset.keys[TRIM_KID] = JWTs.JWKSymmetric("HS256", trim_secret())
    return keyset
end

function trim_payload()::Dict{String,TrimClaimValue}
    payload = Dict{String,TrimClaimValue}()
    payload["iss"] = TRIM_ISSUER
    payload["aud"] = [TRIM_AUDIENCE]
    payload["sub"] = TRIM_SUBJECT
    payload["jti"] = TRIM_JWT_ID
    payload["nonce"] = TRIM_NONCE
    payload["iat"] = 1_000
    payload["nbf"] = 1_000
    payload["exp"] = 2_000
    return payload
end

function trim_check_verified(verified::JWTs.VerifiedJWT)::Nothing
    JWTs.kid(verified) == TRIM_KID || error("unexpected verified kid")
    JWTs.alg(verified) == "HS256" || error("unexpected verified alg")
    claims = JWTs.claims(verified)
    claims["iss"] == TRIM_ISSUER || error("unexpected issuer")
    claims["sub"] == TRIM_SUBJECT || error("unexpected subject")
    return nothing
end

function run_jwt_trim_core()::Nothing
    keyset = trim_keyset()
    jwt = JWTs.JWT(; payload=trim_payload())
    JWTs.sign!(jwt, keyset.keys[TRIM_KID], TRIM_KID)

    token = join((jwt.header::String, jwt.payload, jwt.signature::String), ".")
    parsed = JWTs.JWT(token)
    JWTs.validate!(parsed, keyset.keys[TRIM_KID]; algorithms=["HS256"]) || error("legacy validation failed")

    remote_verifier = JWTs.Verifier(;
        jwks_uri=TRIM_JWKS_URI,
        algorithms=["HS256"],
        issuer=TRIM_ISSUER,
        audience=TRIM_AUDIENCE,
        fetcher=trim_fetch,
        now=trim_now,
    )
    trim_check_verified(JWTs.verify(remote_verifier, token))

    oidc_verifier = JWTs.Verifier(
        TRIM_ISSUER;
        algorithms=["HS256"],
        audience=TRIM_AUDIENCE,
        fetcher=trim_fetch,
        now=trim_now,
    )
    trim_check_verified(JWTs.verify(oidc_verifier, token))
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_jwt_trim_core()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
