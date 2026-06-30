module JWTs

using JSON
using Downloads
using OpenSSL_jll
using SHA

include("errors.jl")
include("crypto.jl")

import Base: getproperty, setproperty!, show, isvalid
export JWT, JWK, JWKRSA, JWKSymmetric, JWKSet
export issigned, isverified, isvalid
export validate!, sign!, refresh!
export show, claims, kid
export with_valid_jwt
export Verifier, VerifiedJWT, verify

struct JWKSymmetric
    alg::String
    key::Vector{UInt8}

    function JWKSymmetric(alg::AbstractString, key::AbstractVector{UInt8})
        alg in HMAC_ALGORITHMS || throw(ArgumentError("unsupported symmetric key algorithm: $alg"))
        new(String(alg), Vector{UInt8}(key))
    end
end

struct JWKRSA
    alg::String
    key::OpenSSLKey

    function JWKRSA(alg::AbstractString, key::OpenSSLKey)
        alg in RSA_ALGORITHMS || throw(ArgumentError("unsupported RSA key algorithm: $alg"))
        new(String(alg), key)
    end
end

struct JWKEC
    alg::String
    key::OpenSSLKey
    crv::String

    function JWKEC(alg::AbstractString, key::OpenSSLKey, crv::AbstractString)
        alg in EC_ALGORITHMS || throw(ArgumentError("unsupported EC key algorithm: $alg"))
        alg == alg_for_curve(crv) || throw(ArgumentError("EC algorithm $alg does not match curve $crv"))
        new(String(alg), key, String(crv))
    end
end

struct JWKOKP
    alg::String
    key::OpenSSLKey
    crv::String

    function JWKOKP(alg::AbstractString, key::OpenSSLKey, crv::AbstractString)
        alg in OKP_ALGORITHMS || throw(ArgumentError("unsupported OKP key algorithm: $alg"))
        alg == alg_for_curve(crv) || throw(ArgumentError("OKP algorithm $alg does not match curve $crv"))
        new(String(alg), key, String(crv))
    end
end

"""
JWK represents a JWK Key (either for signing or verification).

JWK can be a JWKRSA, JWKEC, JWKOKP, or JWKSymmetric. An asymmetric key can
represent either the public or private key.
"""
const JWK = Union{JWKRSA,JWKEC,JWKOKP,JWKSymmetric}

"""
JWKSet holds a set of keys, fetched from a OpenId key URL, each key identified by a key id.

The key URL can either be of `http(s)://` or `file://` type.
"""
mutable struct JWKSet
    url::String
    keys::Dict{String,JWK}

    function JWKSet(url::String)
        new(url, Dict{String,JWK}())
    end

    function JWKSet(keyset::Vector)
        keysetdict = Dict{String,JWK}()
        refresh!(keyset, keysetdict)
        new("", keysetdict)
    end
end
function show(io::IO, jwk::JWKSet)
    print(io, "JWKSet $(length(jwk.keys)) keys")
    isempty(jwk.url) || print(io, " ($(jwk.url))")
end

"""
JWT represents a JWT payload at the minimum.

When signed, it holds the header and signature too.
The parts are stored in encoded form.
"""
struct JWTParts
    payload::String
    header::Union{Nothing,String}
    signature::Union{Nothing,String}
end

mutable struct JWT
    _parts::JWTParts
    _verified::Bool
    _valid::Union{Nothing,Bool}

    function JWT(; jwt::Union{Nothing,String}=nothing, payload=nothing)
        if jwt !== nothing
            (payload === nothing) || throw(ArgumentError("payload must be nothing if jwt is provided"))
            parts = split(jwt, "."; keepempty=true)
            if length(parts) == 3
                new(JWTParts(parts[2], parts[1], parts[3]), false, nothing)
            else
                new(JWTParts("", nothing, nothing), true, false)
            end
        else
            (payload !== nothing) || throw(ArgumentError("payload must be provided if jwt is not"))
            encoded_payload = isa(payload, String) ? payload : base64url_encode(JSON.json(payload))
            new(JWTParts(encoded_payload, nothing, nothing), false, nothing)
        end
    end
end
JWT(jwt::String) = JWT(; jwt=jwt)

function getproperty(jwt::JWT, name::Symbol)
    if name === :payload
        return getfield(jwt, :_parts).payload
    elseif name === :header
        return getfield(jwt, :_parts).header
    elseif name === :signature
        return getfield(jwt, :_parts).signature
    elseif name === :verified
        return getfield(jwt, :_verified)
    elseif name === :valid
        return getfield(jwt, :_valid)
    else
        return getfield(jwt, name)
    end
end

function jwt_encoded_part(value, name::Symbol)::String
    value isa AbstractString || throw(ArgumentError("JWT.$name must be a string"))
    return String(value)
end

function jwt_optional_encoded_part(value, name::Symbol)::Union{Nothing,String}
    value === nothing && return nothing
    return jwt_encoded_part(value, name)
end

function setproperty!(jwt::JWT, name::Symbol, value)
    if name === :payload
        parts = getfield(jwt, :_parts)
        setparts!(jwt, JWTParts(jwt_encoded_part(value, name), parts.header, parts.signature); verified=false, valid=nothing)
    elseif name === :header
        parts = getfield(jwt, :_parts)
        setparts!(jwt, JWTParts(parts.payload, jwt_optional_encoded_part(value, name), parts.signature); verified=false, valid=nothing)
    elseif name === :signature
        parts = getfield(jwt, :_parts)
        setparts!(jwt, JWTParts(parts.payload, parts.header, jwt_optional_encoded_part(value, name)); verified=false, valid=nothing)
    elseif name === :verified || name === :valid
        throw(ArgumentError("JWT.$name is read-only; call sign! or validate! to update validation state"))
    else
        setfield!(jwt, name, value)
    end
    return value
end

function setvalidation!(jwt::JWT, valid::Union{Nothing,Bool})
    setfield!(jwt, :_verified, valid !== nothing)
    setfield!(jwt, :_valid, valid)
    return valid
end

function setparts!(jwt::JWT, parts::JWTParts; verified::Bool=false, valid::Union{Nothing,Bool}=nothing)
    setfield!(jwt, :_parts, parts)
    setfield!(jwt, :_verified, verified)
    setfield!(jwt, :_valid, valid)
    return jwt
end

const JWTJSONDict = Dict{String,Any}

function decodepart(encoded::String)
    json = String(base64url_decode(encoded))
    try
        return JSON.parse(json; dicttype=JWTJSONDict)
    catch
        throw(ArgumentError("JWT part must contain valid JSON"))
    end
end

function decode_jwt_json_object(encoded::String)::JWTJSONDict
    value = decodepart(encoded)
    value isa JWTJSONDict || throw(ArgumentError("JWT part must be a JSON object"))
    return value
end

function jwt_string_claim(claims::AbstractDict, claim::String)::Union{Nothing,String}
    value = get(claims, claim, nothing)
    value isa String || return nothing
    return value
end

function jwt_header_string_claim(encoded::String, claim::String)::Union{Nothing,String}
    return jwt_string_claim(decode_jwt_json_object(encoded), claim)
end

"""
    claims(jwt::JWT)

Get the claims from the JWT payload.
"""
claims(jwt::JWT) = decodepart(jwt.payload)

"""
    issigned(jwt::JWT)

Check if the JWT is signed. Does not check if the JWT is valid.    
Returns `true` if the JWT is signed, `false` otherwise.
"""
issigned(jwt::JWT) = (nothing !== jwt.signature) && (nothing !== jwt.header)

isverified(jwt::JWT) = jwt.verified
isvalid(jwt::JWT) = jwt.valid

"""
    kid(jwt::JWT)

Get the key id from the JWT header, or `nothing` if the `kid` parameter is not included in the JWT header.

The JWT must be signed. An exception is thrown otherwise.
"""
function kid(jwt::JWT)::Union{Nothing,String}
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))
    return jwt_header_string_claim(jwt.header, "kid")
end

"""
    alg(jwt::JWT)

Get the key algorithm from the JWT header, or `nothing` if the `alg` parameter is not included in the JWT header.

The JWT must be signed. An exception is thrown otherwise.
"""
function alg(jwt::JWT)::Union{Nothing,String}
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))
    return jwt_header_string_claim(jwt.header, "alg")
end

"""
    alg(key::JWK)

Get the key algorithm from the JWK key as a string.

Supported algorithms are "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
"PS256", "PS384", "PS512", "ES256", "ES384", "ES512", and "EdDSA".
An `ArgumentError` is thrown for unsupported algorithms.
"""
function alg(key::JWK)
    return key.alg
end

function signbytes(key::JWK, data::AbstractString)
    if key isa JWKSymmetric
        return hmac_digest(alg(key), key.key, data)
    elseif key isa JWKRSA
        return sign_rsa(key.key, alg(key), data)
    elseif key isa JWKEC
        return sign_ec(key.key, alg(key), data)
    else
        return sign_okp(key.key, alg(key), data)
    end
end

function verifybytes(key::JWK, data::AbstractString, signature::AbstractVector{UInt8})
    if key isa JWKSymmetric
        return constant_time_equal(hmac_digest(alg(key), key.key, data), signature)
    elseif key isa JWKRSA
        return verify_rsa(key.key, alg(key), data, signature)
    elseif key isa JWKEC
        return verify_ec(key.key, alg(key), data, signature)
    else
        return verify_okp(key.key, alg(key), data, signature)
    end
end

show(io::IO, jwt::JWT) = print(io, issigned(jwt) ? join([jwt.header, jwt.payload, jwt.signature], '.') : jwt.payload)

"""
    validate!(jwt, keyset)

Validate the JWT using the keys in the keyset.
The JWT must be signed. An exception is thrown otherwise.
The keyset must contain the key id from the JWT header. A KeyError is thrown otherwise.
The optional `algorithms` parameter can be used to specify the algorithms to use for validation.

Returns `true` if the JWT is valid, `false` otherwise.
"""
function validate!(jwt::JWT, keyset::JWKSet; algorithms::Vector{String}=String[])
    keyid = kid(jwt)
    keyid === nothing && throw(ArgumentError("jwt header does not include kid"))
    validate!(jwt, keyset, keyid; algorithms=algorithms)
end
function validate!(jwt::JWT, keyset::JWKSet, kid::String; algorithms::Vector{String}=String[])
    (kid in keys(keyset.keys)) || refresh!(keyset)
    validate!(jwt, keyset.keys[kid]; algorithms=algorithms)
end
function validate!(jwt::JWT, key::JWK; algorithms::Vector{String}=String[])
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))

    data = jwt.header * "." * jwt.payload
    sigbytes = try
        base64url_decode(jwt.signature)
    catch
        return setvalidation!(jwt, false)
    end

    # Check that the (optional) `alg` header claim matches the algorithm of the validation key
    alg_jwt = alg(jwt)
    alg_jwt === nothing && return setvalidation!(jwt, false)
    valid_alg = alg_jwt == alg(key)
    if !isempty(algorithms)
        if !(alg_jwt in algorithms)
            return setvalidation!(jwt, false)
        end
    end
    valid = valid_alg && try
        verifybytes(key, data, sigbytes)
    catch
        false
    end
    return setvalidation!(jwt, valid)
end

"""
    sign!(jwt, keyset, kid)

Sign the JWT using the keys in the keyset. The key id and key algorithm is included in the JWT header.
Updates the jwt with the header and signature.
Returns `nothing`.

Arguments:
- `jwt`: The JWT to sign. If the JWT is already signed, it is not signed again.
- `keyset`: The JWKSet to use for signing. Only keys in this keyset are used for signing.
- `kid`: The key id to use for signing. The keyset must contain the key id from the JWT header. A KeyError is thrown otherwise.
"""
function sign!(jwt::JWT, keyset::JWKSet, kid::String)
    issigned(jwt) && return
    (kid in keys(keyset.keys)) || refresh!(keyset)
    sign!(jwt::JWT, keyset.keys[kid], kid)
end

"""
    sign!(jwt, key, kid)

Sign the JWT using the key. The key id and key algorithm is included in the JWT header.
Updates the jwt with the header and signature.
Returns `nothing`.

Arguments:
- `jwt`: The JWT to sign. If the JWT is already signed, it is not signed again.
- `key`: The JWK to use for signing.
- `kid`: The key id to include in the JWT header.
"""
function sign!(jwt::JWT, key::JWK, kid::String="")
    issigned(jwt) && return

    header_dict = Dict{String,String}("alg"=>alg(key), "typ"=>"JWT")
    isempty(kid) || (header_dict["kid"] = kid)
    header = base64url_encode(JSON.json(header_dict))

    data = header * "." * jwt.payload
    sigbytes = signbytes(key, data)
    signature = base64url_encode(sigbytes)

    setparts!(jwt, JWTParts(jwt.payload, header, signature); verified=true, valid=true)
    nothing
end

"""
    refresh!(keyset, keyseturl; default_algs)
    refresh!(keyset; default_algs)

Arguments:
- `keyset`: The JWKSet to refresh.
- `keyseturl`: The URL to fetch the keys from.

Keyword arguments:
- `default_algs`: A dictionary of default algorithms to use for each key type.

Refresh the keyset with the keys from the keyseturl. The keyseturl can either be of `http(s)://` or `file://` type.
The keyset is updated with the keys from the keyseturl, old keys are removed.

If the keyseturl is not specified, the keyset is refreshed with the keys from the keyseturl already set in the keyset.

The default algorithm values are referred to only if the keyset does not specify the exact algorithm type.
E.g. if only "RSA" is specified as the algorithm, "RS256" will be assumed.
"""
function refresh!(keyset::JWKSet, keyseturl::String; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"), downloader=nothing)
    keyset.url = keyseturl
    refresh!(keyset; default_algs=default_algs, downloader=downloader)
end

function refresh!(keyset::JWKSet; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"), downloader=nothing)
    if !isempty(keyset.url)
        keys = Dict{String,JWK}()
        refresh!(keyset.url, keys; default_algs=default_algs, downloader=downloader)
        keyset.keys = keys
    end
    nothing
end

function fetch_url(url::String; downloader=nothing)
    if startswith(url, "file://")
        return readchomp(url[8:end])
    else
        output = PipeBuffer()
        Downloads.request(url; method="GET", output=output, downloader=downloader)
        return String(take!(output))
    end
end

function refresh!(keyseturl::String, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"), downloader=nothing)
    jstr = fetch_url(keyseturl; downloader=downloader)
    keys = JSON.parse(jstr)["keys"]
    refresh!(keys, keysetdict; default_algs=default_algs)
end

function default_jwk_alg(key, default_algs)
    haskey(key, "alg") && return key["alg"]
    kty = key["kty"]
    if kty in ("EC", "OKP")
        return alg_for_curve(key["crv"])
    else
        return get(default_algs, kty, "none")
    end
end

function refresh!(keys::Vector, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    for key in keys
        kid = key["kid"]
        kty = key["kty"]
        alg = default_jwk_alg(key, default_algs)

        # ref: https://tools.ietf.org/html/rfc7518
        try
            if kty == "RSA"
                n = base64url_decode(key["n"])
                e = base64url_decode(key["e"])
                if alg in RSA_ALGORITHMS
                    keysetdict[kid] = JWKRSA(alg, rsa_public_key(n, e))
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "oct"
                k = base64url_decode(key["k"])
                if alg in HMAC_ALGORITHMS
                    keysetdict[kid] = JWKSymmetric(alg, k)
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "EC"
                crv = key["crv"]
                x = base64url_decode(key["x"])
                y = base64url_decode(key["y"])
                if alg in EC_ALGORITHMS
                    keysetdict[kid] = JWKEC(alg, ec_public_key(crv, x, y), crv)
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "OKP"
                crv = key["crv"]
                x = base64url_decode(key["x"])
                if alg in OKP_ALGORITHMS
                    keysetdict[kid] = JWKOKP(alg, okp_public_key(crv, x), crv)
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            else
                @warn("key type $kty not supported yet, skipping key $kid")
                continue
            end
        catch
            @warn("exception trying to decode, skipping key $kid")
        end
    end
    nothing
end

function urldec(bs)
    bs = replace(bs, "-"=>"+")
    bs = replace(bs, "_"=>"/")
    padb64(bs)
end

function urlenc(bs)
    bs = replace(bs, "+"=>"-")
    bs = replace(bs, "/"=>"_")
    bs = replace(bs, "="=>"")
    bs
end

function padb64(bs)
    surplus = length(bs) % 4
    if surplus > 0
        bs = bs * "="^(4 - surplus)
    end
    bs
end

const BASE64URL_ENCODE_TABLE = codeunits("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
const BASE64URL_INVALID = Int16(-1)

function base64url_value(c::UInt8)::Int16
    UInt8('A') <= c <= UInt8('Z') && return Int16(c - UInt8('A'))
    UInt8('a') <= c <= UInt8('z') && return Int16(c - UInt8('a') + 26)
    UInt8('0') <= c <= UInt8('9') && return Int16(c - UInt8('0') + 52)
    (c == UInt8('-') || c == UInt8('+')) && return 62
    (c == UInt8('_') || c == UInt8('/')) && return 63
    return BASE64URL_INVALID
end

function base64url_encode(data::AbstractVector{UInt8})::String
    bytes = data
    out = UInt8[]
    sizehint!(out, cld(length(bytes) * 4, 3))
    i = firstindex(bytes)
    last_i = lastindex(bytes)
    while i <= last_i
        b1 = bytes[i]
        if i == last_i
            push!(out, BASE64URL_ENCODE_TABLE[(b1 >> 2) + 1])
            push!(out, BASE64URL_ENCODE_TABLE[((b1 & 0x03) << 4) + 1])
            break
        end
        b2 = bytes[i + 1]
        if i + 1 == last_i
            push!(out, BASE64URL_ENCODE_TABLE[(b1 >> 2) + 1])
            push!(out, BASE64URL_ENCODE_TABLE[(((b1 & 0x03) << 4) | (b2 >> 4)) + 1])
            push!(out, BASE64URL_ENCODE_TABLE[((b2 & 0x0f) << 2) + 1])
            break
        end
        b3 = bytes[i + 2]
        push!(out, BASE64URL_ENCODE_TABLE[(b1 >> 2) + 1])
        push!(out, BASE64URL_ENCODE_TABLE[(((b1 & 0x03) << 4) | (b2 >> 4)) + 1])
        push!(out, BASE64URL_ENCODE_TABLE[(((b2 & 0x0f) << 2) | (b3 >> 6)) + 1])
        push!(out, BASE64URL_ENCODE_TABLE[(b3 & 0x3f) + 1])
        i += 3
    end
    return String(out)
end

base64url_encode(data::AbstractString)::String = base64url_encode(collect(codeunits(data)))

function base64url_decode(data::AbstractString)::Vector{UInt8}
    out = UInt8[]
    sizehint!(out, (ncodeunits(data) * 3) >>> 2)
    buffer = UInt32(0)
    bits = 0
    for c in codeunits(data)
        c == UInt8('=') && break
        value = base64url_value(c)
        value == BASE64URL_INVALID && throw(ArgumentError("invalid base64url character"))
        buffer = (buffer << 6) | UInt32(value)
        bits += 6
        if bits >= 8
            bits -= 8
            push!(out, UInt8((buffer >> bits) & 0xff))
        end
    end
    return out
end

"""
    with_valid_jwt(f, jwt, keyset; kid=nothing)

Run `f` with a valid JWT. The validated JWT is passed as an argument to `f`. If the JWT is invalid, an `ArgumentError` is thrown.

Arguments:
- `f`: The function to execute with a valid JWT. The validated JWT is passed as an argument to `f`.
- `jwt`: The JWT string or JWT object to use. If a string is passed, it is converted to a JWT object.
- `keyset`: The JWKSet to use for validation. Only keys in this keyset are used for validation.

Keyword arguments:
- `kid`: The key id to use for validation. If not specified, the `kid` from the JWT header is used.
- `algorithms`: Ensure validation with one of the listed algorithms. Not enforced by deault.
"""
function with_valid_jwt(f::Function, jwt::String, keyset::JWKSet;
    kid::Union{Nothing,String}=nothing,
    algorithms::Vector{String}=String[],
)
    with_valid_jwt(f, JWT(jwt), keyset; kid=kid, algorithms=algorithms)
end
function with_valid_jwt(f::Function, jwt::JWT, keyset::JWKSet;
    kid::Union{Nothing,String}=nothing,
    algorithms::Vector{String}=String[],
)
    if isnothing(kid)
        valid = validate!(jwt, keyset; algorithms=algorithms)
    else
        valid = validate!(jwt, keyset, kid; algorithms=algorithms)
    end

    valid || throw(ArgumentError("invalid jwt"))

    return f(jwt)
end

include("remote_jwks.jl")
include("verifier.jl")

end # module JWTs
