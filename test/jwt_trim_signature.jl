using JWTs

const TRIM_SIGNATURE_KID = "trim-hs256"
const TRIM_SIGNATURE_SECRET = UInt8[
    0x74, 0x72, 0x69, 0x6d, 0x2d, 0x63, 0x6f, 0x6d,
    0x70, 0x69, 0x6c, 0x65, 0x2d, 0x73, 0x65, 0x63,
    0x72, 0x65, 0x74,
]

function trim_signature_key()::JWTs.JWKSymmetric
    return JWTs.JWKSymmetric("HS256", TRIM_SIGNATURE_SECRET)
end

function trim_signature_payload()
    payload = Dict{String,String}()
    payload["iss"] = "https://issuer.example"
    payload["sub"] = "trim-subject"
    payload["aud"] = "api://trim"
    return payload
end

function trim_signature_token(jwt::JWTs.JWT)::String
    return join((jwt.header::String, jwt.payload, jwt.signature::String), ".")
end

function run_jwt_trim_signature()::Nothing
    key = trim_signature_key()
    jwt = JWTs.JWT(; payload=trim_signature_payload())
    JWTs.sign!(jwt, key, TRIM_SIGNATURE_KID)
    token = trim_signature_token(jwt)

    parsed = JWTs.JWT(token)
    JWTs.issigned(parsed) || error("expected signed JWT")
    # JSON.jl parsing is intentionally covered by ordinary tests; it is not trim-clean today.
    data = (parsed.header::String) * "." * parsed.payload
    signature = JWTs.base64url_decode(parsed.signature::String)
    JWTs.verifybytes(key, data, signature) || error("signature validation failed")

    tampered = JWTs.JWT(token[1:end - 1] * (last(token) == 'A' ? "B" : "A"))
    tampered_data = (tampered.header::String) * "." * tampered.payload
    tampered_signature = JWTs.base64url_decode(tampered.signature::String)
    JWTs.verifybytes(key, tampered_data, tampered_signature) && error("tampered signature validated")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_jwt_trim_signature()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
