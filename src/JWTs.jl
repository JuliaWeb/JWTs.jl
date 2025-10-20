module JWTs

using MbedTLS
using JSON
using Base64
using Downloads
using Random

import Base: show, isvalid
export JWT, JWK, JWKRSA, JWKSymmetric, JWKSet
export issigned, isverified, isvalid
export validate!, sign!, refresh!
export show, claims, kid
export with_valid_jwt

struct JWKSymmetric
    kind::MbedTLS.MDKind
    key::Vector{UInt8}
end

struct JWKRSA
    kind::MbedTLS.MDKind
    key::Union{RSA,MbedTLS.PKContext}
end

"""
JWK represents a JWK Key (either for signing or verification).

JWK can be either a JWKRSA or JWKSymmetric. A RSA key can
represent either the public or private key.
"""
const JWK = Union{JWKRSA,JWKSymmetric}

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
mutable struct JWT
    payload::String
    header::Union{Nothing,String}
    signature::Union{Nothing,String}
    verified::Bool
    valid::Union{Nothing,Bool}

    function JWT(; jwt::Union{Nothing,String}=nothing, payload=nothing)
        if jwt !== nothing
            (payload === nothing) || throw(ArgumentError("payload must be nothing if jwt is provided"))
            parts = split(jwt, ".")
            if length(parts) == 3
                new(parts[2], parts[1], parts[3], false, nothing)
            else
                new("", nothing, nothing, true, false)
            end
        else
            (payload !== nothing) || throw(ArgumentError("payload must be provided if jwt is not"))
            new(isa(payload, String) ? payload : urlenc(base64encode(JSON.json(payload))), nothing, nothing, false, nothing)
        end
    end
end

decodepart(encoded::String) = JSON.parse(String(base64decode(urldec(encoded))))

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
function kid(jwt::JWT)::String
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))
    get(decodepart(jwt.header), "kid", nothing)
end

"""
    alg(jwt::JWT)

Get the key algorithm from the JWT header, or `nothing` if the `alg` parameter is not included in the JWT header.

The JWT must be signed. An exception is thrown otherwise.
"""
function alg(jwt::JWT)::String
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))
    get(decodepart(jwt.header), "alg", nothing)
end

"""
    alg(key::JWK)

Get the key algorithm from the JWK key as a string.

Supported algorithms are "RS256", "RS384", "RS512", "HS256", "HS384", and "HS512".
An `ArgumentError` is thrown for unsupported algorithms.
"""
function alg(key::JWK)
    kind = key.kind
    if !(kind === MbedTLS.MD_SHA256 || kind === MbedTLS.MD_SHA384 || kind === MbedTLS.MD_SHA)
        throw(ArgumentError("unsupported key algorithm: $(kind)"))
    end
    return string(key isa JWKRSA ? "RS" : "HS", MbedTLS.get_size(kind) << 3)
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
validate!(jwt::JWT, keyset::JWKSet; algorithms::Vector{String}=String[]) = validate!(jwt, keyset, kid(jwt); algorithms=algorithms)
function validate!(jwt::JWT, keyset::JWKSet, kid::String; algorithms::Vector{String}=String[])
    isverified(jwt) && (return isvalid(jwt))
    (kid in keys(keyset.keys)) || refresh!(keyset)
    validate!(jwt, keyset.keys[kid]; algorithms=algorithms)
end
function validate!(jwt::JWT, key::JWK; algorithms::Vector{String}=String[])
    isverified(jwt) && (return isvalid(jwt))
    issigned(jwt) || throw(ArgumentError("jwt is not signed"))

    data = jwt.header * "." * jwt.payload
    sigbytes = base64decode(urldec(jwt.signature))

    jwt.verified = true
    # Check that the (optional) `alg` header claim matches the algorithm of the validation key
    alg_jwt = alg(jwt)
    valid_alg = alg_jwt === nothing || alg_jwt == alg(key)
    if !isempty(algorithms)
        alg_matched = alg_jwt === nothing ? alg(key) : alg_jwt
        if !(alg_matched in algorithms)
            return false
        end
    end
    jwt.valid = valid_alg && if key isa JWKRSA
        try
            MbedTLS.verify(key.key, key.kind, MbedTLS.digest(key.kind, data), sigbytes) == 0
        catch
            false
        end
    else
        MbedTLS.digest(key.kind, data, key.key) == sigbytes
    end
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
    header = urlenc(base64encode(JSON.json(header_dict)))

    data = header * "." * jwt.payload
    sigbytes = key isa JWKRSA ?  MbedTLS.sign(key.key, key.kind, MbedTLS.digest(key.kind, data), MersenneTwister()) : MbedTLS.digest(key.kind, data, key.key)
    signature = urlenc(base64encode(sigbytes))

    jwt.header = header
    jwt.signature = signature
    jwt.verified = true
    jwt.valid = true
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

function refresh!(keyseturl::String, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"), downloader=nothing)
    if startswith(keyseturl, "file://")
        jstr = readchomp(keyseturl[8:end])
    else
        output = PipeBuffer()
        Downloads.request(keyseturl; method="GET", output=output, downloader=downloader)
        jstr = String(take!(output))
    end
    keys = JSON.parse(jstr)["keys"]
    refresh!(keys, keysetdict; default_algs=default_algs)
end

function refresh!(keys::Vector, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    for key in keys
        kid = key["kid"]
        kty = key["kty"]
        alg = get(key, "alg", get(default_algs, kty, "none"))

        # ref: https://tools.ietf.org/html/rfc7518
        try
            if kty == "RSA"
                n = base64decode(urldec(key["n"]))
                e = base64decode(urldec(key["e"]))
                if alg == "RS256"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA256, pubkey(n, e, MbedTLS.MD_SHA256))
                elseif alg == "RS384"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA384, pubkey(n, e, MbedTLS.MD_SHA384))
                elseif alg == "RS512"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA, pubkey(n, e, MbedTLS.MD_SHA))
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "oct"
                k = base64decode(urldec(key["k"]))
                if alg == "HS256"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA256, k)
                elseif alg == "HS384"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA384, k)
                elseif alg == "HS512"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA, k)
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            else
                @warn("key type $kty not supported yet, skipping key $kid")
                continue
            end
        catch ex
            @warn("exception $ex trying to decode, skipping key $kid")
        end
    end
    nothing
end

function pubkey(bytesn, bytese, halg)
    n = parse(BigInt, bytes2hex(bytesn); base=16)
    e = parse(BigInt, bytes2hex(bytese); base=16)

    R = RSA(MbedTLS.MBEDTLS_RSA_PKCS_V15, halg)
    MbedTLS.pubkey_from_vals!(R, e, n)
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
        validate!(jwt, keyset; algorithms=algorithms)
    else
        validate!(jwt, keyset, kid; algorithms=algorithms)
    end

    isvalid(jwt) || throw(ArgumentError("invalid jwt"))

    return f(jwt)
end

end # module JWTs
