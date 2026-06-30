using JWTs

const TRIM_KID = "trim-hs256"
const TRIM_ISSUER = "https://issuer.example"
const TRIM_AUDIENCE = "api://trim"
const TRIM_SUBJECT = "trim-subject"
const TRIM_JWT_ID = "trim-jti"
const TRIM_NONCE = "trim-nonce"
const TrimClaimValue = Union{Int64,String,Vector{String}}

trim_secret()::Vector{UInt8} = collect(codeunits("trim-compile-secret-material"))

function trim_oct_jwk()
    return Dict(
        "kid" => TRIM_KID,
        "kty" => "oct",
        "alg" => "HS256",
        "k" => JWTs.base64url_encode(trim_secret()),
    )
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

function trim_check_signature(jwt::JWTs.JWT, key::JWTs.JWK)::Nothing
    data = (jwt.header::String) * "." * jwt.payload
    signature = JWTs.base64url_decode(jwt.signature::String)
    JWTs.verifybytes(key, data, signature) || error("signature validation failed")
    return nothing
end

function run_jwt_trim_core()::Nothing
    keyset = trim_keyset()
    jwt = JWTs.JWT(; payload=trim_payload())
    JWTs.sign!(jwt, keyset.keys[TRIM_KID], TRIM_KID)

    token = join((jwt.header::String, jwt.payload, jwt.signature::String), ".")
    parsed = JWTs.JWT(token)
    # JSON.jl parsing is intentionally covered by ordinary tests; it is not trim-clean today.
    trim_check_signature(parsed, keyset.keys[TRIM_KID])

    imported_keyset = JWTs.JWKSet([trim_oct_jwk()])
    trim_check_signature(parsed, imported_keyset.keys[TRIM_KID])
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_jwt_trim_core()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
