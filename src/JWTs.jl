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

function setproperty!(jwt::JWT, name::Symbol, value)
    if name in (:payload, :header, :signature, :verified, :valid)
        throw(ArgumentError("JWT.$name is read-only"))
    else
        setfield!(jwt, name, value)
    end
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

decodepart(encoded::String) = JSON.parse(String(base64url_decode(encoded)))

function json_skip_ws(bytes, i::Int, last_i::Int)::Int
    while i <= last_i
        c = bytes[i]
        if c == UInt8(' ') || c == UInt8('\t') || c == UInt8('\n') || c == UInt8('\r')
            i += 1
        else
            break
        end
    end
    return i
end

function json_append_segment!(out::Vector{UInt8}, bytes, first_i::Int, last_i::Int)::Nothing
    i = first_i
    while i <= last_i
        push!(out, bytes[i])
        i += 1
    end
    return nothing
end

function json_hex_value(c::UInt8)::Int
    UInt8('0') <= c <= UInt8('9') && return Int(c - UInt8('0'))
    UInt8('a') <= c <= UInt8('f') && return Int(c - UInt8('a') + 10)
    UInt8('A') <= c <= UInt8('F') && return Int(c - UInt8('A') + 10)
    return -1
end

function json_parse_unicode_escape(bytes, i::Int, last_i::Int)::Tuple{Int,Int}
    value = 0
    for _ = 1:4
        i <= last_i || throw(ArgumentError("unterminated JSON unicode escape"))
        digit = json_hex_value(bytes[i])
        digit >= 0 || throw(ArgumentError("invalid JSON unicode escape"))
        value = (value << 4) + digit
        i += 1
    end
    return value, i
end

function json_append_codepoint!(out::Vector{UInt8}, codepoint::Int)::Nothing
    append!(out, codeunits(string(Char(codepoint))))
    return nothing
end

function json_parse_string(bytes, i::Int, last_i::Int)::Tuple{String,Int}
    i <= last_i && bytes[i] == UInt8('"') || throw(ArgumentError("expected JSON string"))
    i += 1
    segment_start = i
    out = UInt8[]
    while i <= last_i
        c = bytes[i]
        if c == UInt8('"')
            json_append_segment!(out, bytes, segment_start, i - 1)
            return String(out), i + 1
        elseif c == UInt8('\\')
            json_append_segment!(out, bytes, segment_start, i - 1)
            i += 1
            i <= last_i || throw(ArgumentError("unterminated JSON escape"))
            esc = bytes[i]
            if esc == UInt8('"') || esc == UInt8('\\') || esc == UInt8('/')
                push!(out, esc)
                i += 1
            elseif esc == UInt8('b')
                push!(out, 0x08)
                i += 1
            elseif esc == UInt8('f')
                push!(out, 0x0c)
                i += 1
            elseif esc == UInt8('n')
                push!(out, UInt8('\n'))
                i += 1
            elseif esc == UInt8('r')
                push!(out, UInt8('\r'))
                i += 1
            elseif esc == UInt8('t')
                push!(out, UInt8('\t'))
                i += 1
            elseif esc == UInt8('u')
                codepoint, i = json_parse_unicode_escape(bytes, i + 1, last_i)
                if 0xd800 <= codepoint <= 0xdbff
                    i + 1 <= last_i && bytes[i] == UInt8('\\') && bytes[i + 1] == UInt8('u') ||
                        throw(ArgumentError("invalid JSON surrogate pair"))
                    low, i = json_parse_unicode_escape(bytes, i + 2, last_i)
                    0xdc00 <= low <= 0xdfff || throw(ArgumentError("invalid JSON surrogate pair"))
                    codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00)
                elseif 0xdc00 <= codepoint <= 0xdfff
                    throw(ArgumentError("invalid JSON surrogate pair"))
                end
                json_append_codepoint!(out, codepoint)
            else
                throw(ArgumentError("invalid JSON escape"))
            end
            segment_start = i
        elseif c < 0x20
            throw(ArgumentError("invalid JSON string control character"))
        else
            i += 1
        end
    end
    throw(ArgumentError("unterminated JSON string"))
end

function json_skip_string(bytes, i::Int, last_i::Int)::Int
    i <= last_i && bytes[i] == UInt8('"') || throw(ArgumentError("expected JSON string"))
    i += 1
    while i <= last_i
        c = bytes[i]
        if c == UInt8('"')
            return i + 1
        elseif c == UInt8('\\')
            i += 2
        elseif c < 0x20
            throw(ArgumentError("invalid JSON string control character"))
        else
            i += 1
        end
    end
    throw(ArgumentError("unterminated JSON string"))
end

function json_skip_value(bytes, i::Int, last_i::Int)::Int
    i = json_skip_ws(bytes, i, last_i)
    i <= last_i || throw(ArgumentError("expected JSON value"))
    c = bytes[i]
    if c == UInt8('"')
        return json_skip_string(bytes, i, last_i)
    elseif c == UInt8('{') || c == UInt8('[')
        depth = 1
        i += 1
        while i <= last_i
            c = bytes[i]
            if c == UInt8('"')
                i = json_skip_string(bytes, i, last_i)
            elseif c == UInt8('{') || c == UInt8('[')
                depth += 1
                i += 1
            elseif c == UInt8('}') || c == UInt8(']')
                depth -= 1
                i += 1
                depth == 0 && return i
            else
                i += 1
            end
        end
        throw(ArgumentError("unterminated JSON container"))
    else
        while i <= last_i
            c = bytes[i]
            (c == UInt8(',') || c == UInt8('}') || c == UInt8(']')) && return i
            i += 1
        end
        return i
    end
end

function jwt_header_string_claim(encoded::String, claim::String)::Union{Nothing,String}
    json = String(base64url_decode(encoded))
    bytes = codeunits(json)
    last_i = ncodeunits(json)
    i = json_skip_ws(bytes, 1, last_i)
    i <= last_i && bytes[i] == UInt8('{') || throw(ArgumentError("jwt header must be a JSON object"))
    i += 1
    found::Union{Nothing,String} = nothing
    while true
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated jwt header"))
        if bytes[i] == UInt8('}')
            i = json_skip_ws(bytes, i + 1, last_i)
            i > last_i || throw(ArgumentError("trailing data after jwt header"))
            return found
        end
        key, i = json_parse_string(bytes, i, last_i)
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i && bytes[i] == UInt8(':') || throw(ArgumentError("expected ':' in jwt header"))
        i = json_skip_ws(bytes, i + 1, last_i)
        if key == claim
            if i <= last_i && bytes[i] == UInt8('"')
                found, i = json_parse_string(bytes, i, last_i)
            else
                found = nothing
                i = json_skip_value(bytes, i, last_i)
            end
        else
            i = json_skip_value(bytes, i, last_i)
        end
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated jwt header"))
        if bytes[i] == UInt8(',')
            i += 1
        elseif bytes[i] == UInt8('}')
            i = json_skip_ws(bytes, i + 1, last_i)
            i > last_i || throw(ArgumentError("trailing data after jwt header"))
            return found
        else
            throw(ArgumentError("expected ',' or '}' in jwt header"))
        end
    end
end

const JWTDecodedValue = Union{Nothing,Bool,Int64,Float64,String,Vector{Any},Dict{String,Any}}

function json_consume_literal(bytes, i::Int, last_i::Int, literal::String)::Int
    for c in codeunits(literal)
        i <= last_i && bytes[i] == c || throw(ArgumentError("invalid JSON literal"))
        i += 1
    end
    return i
end

function json_parse_number(bytes, i::Int, last_i::Int)::Tuple{Union{Int64,Float64},Int}
    negative = false
    if i <= last_i && bytes[i] == UInt8('-')
        negative = true
        i += 1
    end

    i <= last_i || throw(ArgumentError("expected JSON number"))
    int_value = Int64(0)
    digits = 0
    if bytes[i] == UInt8('0')
        digits = 1
        i += 1
    elseif UInt8('1') <= bytes[i] <= UInt8('9')
        while i <= last_i && UInt8('0') <= bytes[i] <= UInt8('9')
            int_value = int_value * 10 + Int64(bytes[i] - UInt8('0'))
            digits += 1
            i += 1
        end
    else
        throw(ArgumentError("expected JSON number"))
    end
    digits > 0 || throw(ArgumentError("expected JSON number"))

    is_float = false
    float_value = Float64(int_value)
    if i <= last_i && bytes[i] == UInt8('.')
        is_float = true
        i += 1
        i <= last_i && UInt8('0') <= bytes[i] <= UInt8('9') || throw(ArgumentError("expected JSON fraction digit"))
        scale = 0.1
        while i <= last_i && UInt8('0') <= bytes[i] <= UInt8('9')
            float_value += Float64(bytes[i] - UInt8('0')) * scale
            scale *= 0.1
            i += 1
        end
    end

    if i <= last_i && (bytes[i] == UInt8('e') || bytes[i] == UInt8('E'))
        is_float = true
        i += 1
        exp_negative = false
        if i <= last_i && (bytes[i] == UInt8('+') || bytes[i] == UInt8('-'))
            exp_negative = bytes[i] == UInt8('-')
            i += 1
        end
        i <= last_i && UInt8('0') <= bytes[i] <= UInt8('9') || throw(ArgumentError("expected JSON exponent digit"))
        exponent = 0
        while i <= last_i && UInt8('0') <= bytes[i] <= UInt8('9')
            exponent = exponent * 10 + Int(bytes[i] - UInt8('0'))
            i += 1
        end
        float_value *= 10.0 ^ (exp_negative ? -exponent : exponent)
    end

    if is_float
        return negative ? -float_value : float_value, i
    else
        return negative ? -int_value : int_value, i
    end
end

function json_parse_array(bytes, i::Int, last_i::Int)::Tuple{Vector{Any},Int}
    i <= last_i && bytes[i] == UInt8('[') || throw(ArgumentError("expected JSON array"))
    i += 1
    values = Any[]
    while true
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JSON array"))
        if bytes[i] == UInt8(']')
            return values, i + 1
        end
        value, i = json_parse_value(bytes, i, last_i)
        push!(values, value)
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JSON array"))
        if bytes[i] == UInt8(',')
            i += 1
        elseif bytes[i] == UInt8(']')
            return values, i + 1
        else
            throw(ArgumentError("expected ',' or ']' in JSON array"))
        end
    end
end

function json_parse_object_any(bytes, i::Int, last_i::Int)::Tuple{Dict{String,Any},Int}
    i <= last_i && bytes[i] == UInt8('{') || throw(ArgumentError("expected JSON object"))
    i += 1
    obj = Dict{String,Any}()
    while true
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JSON object"))
        if bytes[i] == UInt8('}')
            return obj, i + 1
        end
        key, i = json_parse_string(bytes, i, last_i)
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i && bytes[i] == UInt8(':') || throw(ArgumentError("expected ':' in JSON object"))
        parsed_value = json_parse_value(bytes, i + 1, last_i)
        value = parsed_value[1]::JWTDecodedValue
        i = parsed_value[2]
        obj[key] = value
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JSON object"))
        if bytes[i] == UInt8(',')
            i += 1
        elseif bytes[i] == UInt8('}')
            return obj, i + 1
        else
            throw(ArgumentError("expected ',' or '}' in JSON object"))
        end
    end
end

function json_parse_value(bytes, i::Int, last_i::Int)::Tuple{JWTDecodedValue,Int}
    i = json_skip_ws(bytes, i, last_i)
    i <= last_i || throw(ArgumentError("expected JSON value"))
    c = bytes[i]
    if c == UInt8('"')
        return json_parse_string(bytes, i, last_i)
    elseif c == UInt8('{')
        return json_parse_object_any(bytes, i, last_i)
    elseif c == UInt8('[')
        return json_parse_array(bytes, i, last_i)
    elseif c == UInt8('t')
        return true, json_consume_literal(bytes, i, last_i, "true")
    elseif c == UInt8('f')
        return false, json_consume_literal(bytes, i, last_i, "false")
    elseif c == UInt8('n')
        return nothing, json_consume_literal(bytes, i, last_i, "null")
    elseif c == UInt8('-') || UInt8('0') <= c <= UInt8('9')
        return json_parse_number(bytes, i, last_i)
    else
        throw(ArgumentError("expected JSON value"))
    end
end

function decode_jwt_json_object(encoded::String)::Dict{String,JWTDecodedValue}
    json = String(base64url_decode(encoded))
    bytes = codeunits(json)
    last_i = ncodeunits(json)
    i = json_skip_ws(bytes, 1, last_i)
    i <= last_i && bytes[i] == UInt8('{') || throw(ArgumentError("JWT part must be a JSON object"))
    i += 1
    obj = Dict{String,JWTDecodedValue}()
    while true
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JWT JSON object"))
        if bytes[i] == UInt8('}')
            i = json_skip_ws(bytes, i + 1, last_i)
            i > last_i || throw(ArgumentError("trailing data after JWT JSON object"))
            return obj
        end
        key, i = json_parse_string(bytes, i, last_i)
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i && bytes[i] == UInt8(':') || throw(ArgumentError("expected ':' in JWT JSON object"))
        parsed_value = json_parse_value(bytes, i + 1, last_i)
        value = parsed_value[1]::JWTDecodedValue
        i = parsed_value[2]
        obj[key] = value
        i = json_skip_ws(bytes, i, last_i)
        i <= last_i || throw(ArgumentError("unterminated JWT JSON object"))
        if bytes[i] == UInt8(',')
            i += 1
        elseif bytes[i] == UInt8('}')
            i = json_skip_ws(bytes, i + 1, last_i)
            i > last_i || throw(ArgumentError("trailing data after JWT JSON object"))
            return obj
        else
            throw(ArgumentError("expected ',' or '}' in JWT JSON object"))
        end
    end
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
