module JWTs

using JSON
using Downloads
using OpenSSL_jll
using SHA

include("errors.jl")
include("crypto.jl")

import Base: getproperty, setproperty!, show, isvalid

if VERSION >= v"1.11"
    Core.eval(@__MODULE__, Expr(:public,
        :JWT,
        :JWK,
        :JWKSet,
        :JWKRSA,
        :JWKEC,
        :JWKOKP,
        :JWKSymmetric,
        :Verifier,
        :VerifiedJWT,
        :JWTError,
        :JWTVerificationError,
        :JWTClaimError,
        :JWKSError,
        :parse_keyfile,
        :claims,
        :kid,
        :alg,
        :issigned,
        :isverified,
        :isvalid,
        :sign!,
        :validate!,
        :refresh!,
        :with_valid_jwt,
        :verify,
    ))
end

struct JWKSymmetric
    alg::String
    key::Vector{UInt8}
    _sign_allowed::Bool
    _verify_allowed::Bool

    function JWKSymmetric(
        alg::AbstractString,
        key::AbstractVector{UInt8},
        sign_allowed::Bool,
        verify_allowed::Bool,
    )
        alg in HMAC_ALGORITHMS || throw(ArgumentError("unsupported symmetric key algorithm: $alg"))
        new(String(alg), Vector{UInt8}(key), sign_allowed, verify_allowed)
    end
end
JWKSymmetric(alg::AbstractString, key::AbstractVector{UInt8}) =
    JWKSymmetric(alg, key, true, true)

struct JWKRSA
    alg::String
    key::OpenSSLKey
    _sign_allowed::Bool
    _verify_allowed::Bool

    function JWKRSA(
        alg::AbstractString,
        key::OpenSSLKey,
        sign_allowed::Bool,
        verify_allowed::Bool,
    )
        alg in RSA_ALGORITHMS || throw(ArgumentError("unsupported RSA key algorithm: $alg"))
        new(String(alg), key, sign_allowed, verify_allowed)
    end
end
JWKRSA(alg::AbstractString, key::OpenSSLKey) =
    JWKRSA(alg, key, true, true)

struct JWKEC
    alg::String
    key::OpenSSLKey
    crv::String
    _sign_allowed::Bool
    _verify_allowed::Bool

    function JWKEC(
        alg::AbstractString,
        key::OpenSSLKey,
        crv::AbstractString,
        sign_allowed::Bool,
        verify_allowed::Bool,
    )
        alg in EC_ALGORITHMS || throw(ArgumentError("unsupported EC key algorithm: $alg"))
        alg == alg_for_curve(crv) || throw(ArgumentError("EC algorithm $alg does not match curve $crv"))
        new(String(alg), key, String(crv), sign_allowed, verify_allowed)
    end
end
JWKEC(alg::AbstractString, key::OpenSSLKey, crv::AbstractString) =
    JWKEC(alg, key, crv, true, true)

struct JWKOKP
    alg::String
    key::OpenSSLKey
    crv::String
    _sign_allowed::Bool
    _verify_allowed::Bool

    function JWKOKP(
        alg::AbstractString,
        key::OpenSSLKey,
        crv::AbstractString,
        sign_allowed::Bool,
        verify_allowed::Bool,
    )
        alg in OKP_ALGORITHMS || throw(ArgumentError("unsupported OKP key algorithm: $alg"))
        alg == alg_for_curve(crv) || throw(ArgumentError("OKP algorithm $alg does not match curve $crv"))
        new(String(alg), key, String(crv), sign_allowed, verify_allowed)
    end
end
JWKOKP(alg::AbstractString, key::OpenSSLKey, crv::AbstractString) =
    JWKOKP(alg, key, crv, true, true)

"""
JWK represents a JWK Key (either for signing or verification).

JWK can be a JWKRSA, JWKEC, JWKOKP, or JWKSymmetric. An asymmetric key can
represent either the public or private key.

When a JWK is parsed from a document, its `use` and `key_ops` permissions are
retained and enforced during signing and verification.
"""
const JWK = Union{JWKRSA,JWKEC,JWKOKP,JWKSymmetric}

const DEFAULT_JWK_ALGS = Dict("RSA" => "RS256", "oct" => "HS256")
const DEFAULT_UNKNOWN_KID_REFRESH_COOLDOWN = 30.0

monotonic_seconds() = Float64(time_ns()) / 1.0e9

function normalize_nonnegative_seconds(name::String, value::Real)
    seconds = Float64(value)
    isfinite(seconds) && seconds >= 0 ||
        throw(ArgumentError("$name must be finite and non-negative"))
    return seconds
end

normalize_now_function(now::Function) = now
normalize_now_function(now) = () -> now()

function normalize_default_algs(default_algs)
    return Dict{String,String}(String(k) => String(v) for (k, v) in default_algs)
end

struct UnsetKeyword end
const UNSET_KEYWORD = UnsetKeyword()

"""
    JWKSet(url; refresh_cooldown=30, cache_now=<monotonic clock>,
           default_algs=<RSA/HS defaults>, fetcher=nothing,
           downloader=nothing, allow_symmetric=nothing)
    JWKSet(keys; refresh_cooldown=30, cache_now=<monotonic clock>,
           default_algs=<RSA/HS defaults>, fetcher=nothing,
           downloader=nothing, allow_symmetric=nothing)

Hold keys indexed by key id. A URL may use `http(s)://` or `file://`.

An unrecognised or unresolved key may trigger one automatic refresh per
`refresh_cooldown` seconds. The cache uses a monotonic clock by default. Custom
fetch settings are retained for later automatic refreshes. `default_algs`
defaults RSA keys to `RS256` and symmetric keys to `HS256`.
"""
mutable struct JWKSet
    url::String
    keys::Dict{String,JWK}
    # `lock` protects cached state. `refresh_lock` serializes fetches. Network I/O
    # never holds `lock`, so a slow attacker-triggered refresh cannot block readers
    # that can use an already cached key.
    lock::ReentrantLock
    refresh_lock::ReentrantLock
    refresh_cooldown::Float64
    last_key_miss_refresh_at::Union{Nothing,Float64}
    refresh_generation::UInt64
    cache_now::Function
    default_algs::Dict{String,String}
    fetcher::Any
    downloader::Any
    allow_symmetric::Union{Nothing,Bool}

    function JWKSet(
        url::String;
        refresh_cooldown::Real=DEFAULT_UNKNOWN_KID_REFRESH_COOLDOWN,
        cache_now=monotonic_seconds,
        default_algs=DEFAULT_JWK_ALGS,
        fetcher=nothing,
        downloader=nothing,
        allow_symmetric::Union{Nothing,Bool}=nothing,
    )
        cooldown = normalize_nonnegative_seconds("refresh_cooldown", refresh_cooldown)
        new(
            url,
            Dict{String,JWK}(),
            ReentrantLock(),
            ReentrantLock(),
            cooldown,
            nothing,
            UInt64(0),
            normalize_now_function(cache_now),
            normalize_default_algs(default_algs),
            fetcher,
            downloader,
            allow_symmetric,
        )
    end

    function JWKSet(
        keyset::Vector;
        refresh_cooldown::Real=DEFAULT_UNKNOWN_KID_REFRESH_COOLDOWN,
        cache_now=monotonic_seconds,
        default_algs=DEFAULT_JWK_ALGS,
        fetcher=nothing,
        downloader=nothing,
        allow_symmetric::Union{Nothing,Bool}=nothing,
    )
        cooldown = normalize_nonnegative_seconds("refresh_cooldown", refresh_cooldown)
        keysetdict = Dict{String,JWK}()
        normalized_algs = normalize_default_algs(default_algs)
        refresh!(keyset, keysetdict; default_algs=normalized_algs, allow_symmetric=something(allow_symmetric, true))
        new(
            "",
            keysetdict,
            ReentrantLock(),
            ReentrantLock(),
            cooldown,
            nothing,
            UInt64(0),
            normalize_now_function(cache_now),
            normalized_algs,
            fetcher,
            downloader,
            allow_symmetric,
        )
    end
end

function show(io::IO, jwk::JWKSet)
    url, key_count = lock(jwk.lock) do
        return jwk.url, length(jwk.keys)
    end
    print(io, "JWKSet $key_count keys")
    isempty(url) || print(io, " ($url)")
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

function validate_claims_protected_header(header::AbstractDict)
    has_b64 = haskey(header, "b64")
    if has_b64
        b64 = header["b64"]
        b64 isa Bool || throw(JWTVerificationError(
            :header_parameter_invalid,
            "jwt b64 header parameter must be a boolean"))
        b64 || throw(JWTVerificationError(
            :unencoded_payload_unsupported,
            "JWT payloads must use base64url encoding"))
    end

    if !haskey(header, "crit")
        has_b64 && throw(JWTVerificationError(
            :critical_header_invalid,
            "jwt b64 header parameter must be listed in crit"))
        return nothing
    end
    crit = header["crit"]
    crit isa AbstractVector || throw(JWTVerificationError(
        :critical_header_invalid,
        "jwt crit header parameter must be a non-empty array of strings"))
    isempty(crit) && throw(JWTVerificationError(
        :critical_header_invalid,
        "jwt crit header parameter must not be empty"))

    names = String[]
    for name in crit
        name isa AbstractString || throw(JWTVerificationError(
            :critical_header_invalid,
            "jwt crit header entries must be strings"))
        name_s = String(name)
        name_s in names && throw(JWTVerificationError(
            :critical_header_invalid,
            "jwt crit header entries must be unique"))
        haskey(header, name_s) || throw(JWTVerificationError(
            :critical_header_invalid,
            "jwt critical header parameter $name_s is missing"))
        name_s == "b64" || throw(JWTVerificationError(
            :critical_header_unsupported,
            "jwt critical header parameter $name_s is not supported"))
        push!(names, name_s)
    end
    has_b64 && !("b64" in names) && throw(JWTVerificationError(
        :critical_header_invalid,
        "jwt b64 header parameter must be listed in crit"))
    return nothing
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
    key._sign_allowed ||
        throw(ArgumentError("JWK key operations do not permit signing"))
    if key isa JWKSymmetric
        return hmac_digest(alg(key), key.key, data)
    elseif key isa JWKRSA
        return evp_digest_sign(key.key, alg(key), data)
    elseif key isa JWKEC
        return sign_ec(key.key, alg(key), data)
    else
        return sign_okp(key.key, alg(key), data)
    end
end

function verifybytes(key::JWK, data::AbstractString, signature::AbstractVector{UInt8})
    key._verify_allowed || return false
    if key isa JWKSymmetric
        return constant_time_equal(hmac_digest(alg(key), key.key, data), signature)
    elseif key isa JWKRSA
        return evp_digest_verify(key.key, alg(key), data, signature)
    elseif key isa JWKEC
        return verify_ec(key.key, alg(key), data, signature)
    else
        return verify_okp(key.key, alg(key), data, signature)
    end
end

show(io::IO, jwt::JWT) = print(io, issigned(jwt) ? join([jwt.header, jwt.payload, jwt.signature], '.') : jwt.payload)

"""
    validate!(jwt, keyset)

Validate the JWT **signature** using the keys in the keyset.
The JWT must be signed. An exception is thrown otherwise.
The keyset must contain the key id from the JWT header. A KeyError is thrown otherwise.
The optional `algorithms` parameter can be used to specify the algorithms to use for validation.
A parsed JWK whose `use` or `key_ops` disallows verification returns `false`.

Returns `true` if the signature is valid, `false` otherwise.

!!! warning "Signature only"
    This checks the signature and the `alg` header; it does **not** look at any claims,
    so an expired token validates successfully and [`isvalid`](@ref) reports `true` for it.
    Use [`verify`](@ref) with a [`Verifier`](@ref) to also enforce `exp`, `nbf`, `iat`,
    `iss`, and `aud`, or [`with_valid_jwt`](@ref) which rejects expired tokens.
"""
function validate!(jwt::JWT, keyset::JWKSet; algorithms::Vector{String}=String[])
    keyid = kid(jwt)
    keyid === nothing && throw(ArgumentError("jwt header does not include kid"))
    validate!(jwt, keyset, keyid; algorithms=algorithms)
end
function validate!(jwt::JWT, keyset::JWKSet, kid::String; algorithms::Vector{String}=String[])
    key, generation = jwkset_key_snapshot(keyset, kid)
    if key === nothing
        refresh_for_key_miss!(keyset; observed_generation=generation)
        key, _ = jwkset_key_snapshot(keyset, kid)
    end
    key === nothing && throw(KeyError(kid))
    validate!(jwt, key; algorithms=algorithms)
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

A parsed JWK whose `use` or `key_ops` disallows signing raises `ArgumentError`.
"""
function sign!(jwt::JWT, keyset::JWKSet, kid::String)
    issigned(jwt) && return
    key, _ = jwkset_key_snapshot(keyset, kid)
    if key === nothing
        refresh!(keyset)
        key, _ = jwkset_key_snapshot(keyset, kid)
    end
    key === nothing && throw(KeyError(kid))
    sign!(jwt::JWT, key, kid)
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

A parsed JWK whose `use` or `key_ops` disallows signing raises `ArgumentError`.
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
    refresh!(keyset, keyseturl; default_algs, fetcher, downloader, allow_symmetric)
    refresh!(keyset; default_algs, fetcher, downloader, allow_symmetric)

Arguments:
- `keyset`: The JWKSet to refresh.
- `keyseturl`: The URL to fetch the keys from.

Keyword arguments:
- `default_algs`: A dictionary of default algorithms to use for each key type.
- `fetcher`: A function that fetches the URL and returns bytes, text, or a parsed object.
- `downloader`: A configured `Downloads.Downloader` for the default fetcher.
- `allow_symmetric`: Whether to accept symmetric keys from this source.

Refresh the keyset with the keys from the keyseturl. The keyseturl can either be of `http(s)://` or `file://` type.
The keyset is updated with the keys from the keyseturl, old keys are removed.

If the keyseturl is not specified, the keyset is refreshed with the keys from the keyseturl already set in the keyset.
Explicit URL and keyword overrides are retained for later automatic refreshes.

The default algorithm values are referred to only if the keyset does not specify the exact algorithm type.
E.g. if only "RSA" is specified as the algorithm, "RS256" will be assumed.
"""
function cache_now_seconds(source)
    now_value = Float64(source.cache_now())
    isfinite(now_value) || throw(ArgumentError("cache clock must return a finite number"))
    return now_value
end

function in_cooldown(last_at::Union{Nothing,Float64}, now_value::Float64, cooldown::Float64)
    last_at === nothing && return false
    elapsed = now_value - last_at
    return 0 <= elapsed < cooldown
end

function cache_expired(fetched_at::Union{Nothing,Float64}, now_value::Float64, ttl::Float64)
    fetched_at === nothing && return true
    elapsed = now_value - fetched_at
    return elapsed < 0 || elapsed >= ttl
end

function jwkset_key_snapshot(keyset::JWKSet, keyid::String)
    return lock(keyset.lock) do
        return get(keyset.keys, keyid, nothing), keyset.refresh_generation
    end
end

function jwkset_sole_snapshot(keyset::JWKSet)
    return lock(keyset.lock) do
        generation = keyset.refresh_generation
        key_count = length(keyset.keys)
        if key_count == 1
            keyid = first(keys(keyset.keys))
            return keyid, keyset.keys[keyid], generation, key_count, keyset.url
        end
        return nothing, nothing, generation, key_count, keyset.url
    end
end

function update_jwkset_refresh_config_unlocked!(
    keyset::JWKSet;
    keyseturl=UNSET_KEYWORD,
    default_algs=UNSET_KEYWORD,
    downloader=UNSET_KEYWORD,
    fetcher=UNSET_KEYWORD,
    allow_symmetric=UNSET_KEYWORD,
)
    keyseturl === UNSET_KEYWORD || (keyset.url = String(keyseturl))
    default_algs === UNSET_KEYWORD || (keyset.default_algs = normalize_default_algs(default_algs))
    downloader === UNSET_KEYWORD || (keyset.downloader = downloader)
    fetcher === UNSET_KEYWORD || (keyset.fetcher = fetcher)
    if allow_symmetric !== UNSET_KEYWORD
        allow_symmetric isa Union{Nothing,Bool} ||
            throw(ArgumentError("allow_symmetric must be true, false, or nothing"))
        keyset.allow_symmetric = allow_symmetric
    end
    return nothing
end

function jwkset_refresh_snapshot(
    keyset::JWKSet;
    keyseturl=UNSET_KEYWORD,
    default_algs=UNSET_KEYWORD,
    downloader=UNSET_KEYWORD,
    fetcher=UNSET_KEYWORD,
    allow_symmetric=UNSET_KEYWORD,
)
    return lock(keyset.lock) do
        update_jwkset_refresh_config_unlocked!(
            keyset;
            keyseturl=keyseturl,
            default_algs=default_algs,
            downloader=downloader,
            fetcher=fetcher,
            allow_symmetric=allow_symmetric,
        )
        return (
            url=keyset.url,
            default_algs=copy(keyset.default_algs),
            downloader=keyset.downloader,
            fetcher=keyset.fetcher,
            allow_symmetric=keyset.allow_symmetric,
        )
    end
end

function install_jwkset_keys!(keyset::JWKSet, keys::Dict{String,JWK})
    return lock(keyset.lock) do
        keyset.keys = keys
        keyset.refresh_generation += UInt64(1)
        return keyset.refresh_generation
    end
end

function refresh_jwkset_locked!(
    keyset::JWKSet;
    keyseturl=UNSET_KEYWORD,
    default_algs=UNSET_KEYWORD,
    downloader=UNSET_KEYWORD,
    fetcher=UNSET_KEYWORD,
    allow_symmetric=UNSET_KEYWORD,
)
    config = jwkset_refresh_snapshot(
        keyset;
        keyseturl=keyseturl,
        default_algs=default_algs,
        downloader=downloader,
        fetcher=fetcher,
        allow_symmetric=allow_symmetric,
    )
    isempty(config.url) && return false

    keys = Dict{String,JWK}()
    refresh!(
        config.url,
        keys;
        default_algs=config.default_algs,
        downloader=config.downloader,
        fetcher=config.fetcher,
        allow_symmetric=config.allow_symmetric,
    )
    install_jwkset_keys!(keyset, keys)
    return true
end

function refresh!(keyset::JWKSet, keyseturl::String; default_algs=UNSET_KEYWORD,
    downloader=UNSET_KEYWORD, fetcher=UNSET_KEYWORD, allow_symmetric=UNSET_KEYWORD)
    lock(keyset.refresh_lock) do
        refresh_jwkset_locked!(
            keyset;
            keyseturl=keyseturl,
            default_algs=default_algs,
            downloader=downloader,
            fetcher=fetcher,
            allow_symmetric=allow_symmetric,
        )
    end
    return nothing
end

function refresh!(keyset::JWKSet; default_algs=UNSET_KEYWORD,
    downloader=UNSET_KEYWORD, fetcher=UNSET_KEYWORD, allow_symmetric=UNSET_KEYWORD)
    lock(keyset.refresh_lock) do
        refresh_jwkset_locked!(
            keyset;
            default_algs=default_algs,
            downloader=downloader,
            fetcher=fetcher,
            allow_symmetric=allow_symmetric,
        )
    end
    return nothing
end

# Token-controlled key misses share one refresh budget. Fetches are serialized, but
# the state lock is released during I/O so cached-key verification can continue.
function refresh_for_key_miss!(
    keyset::JWKSet;
    observed_generation::Union{Nothing,UInt64}=nothing,
)
    lock(keyset.refresh_lock)
    try
        now_value = cache_now_seconds(keyset)
        generation, last_refresh, cooldown, url = lock(keyset.lock) do
            return (
                keyset.refresh_generation,
                keyset.last_key_miss_refresh_at,
                keyset.refresh_cooldown,
                keyset.url,
            )
        end
        observed_generation !== nothing && generation != observed_generation && return true
        isempty(url) && return false
        in_cooldown(last_refresh, now_value, cooldown) && return false

        try
            return refresh_jwkset_locked!(keyset)
        finally
            completed_at = cache_now_seconds(keyset)
            lock(keyset.lock) do
                keyset.last_key_miss_refresh_at = completed_at
            end
        end
    finally
        unlock(keyset.refresh_lock)
    end
end

function refresh_for_unknown_kid!(keyset::JWKSet, keyid::String)
    key, generation = jwkset_key_snapshot(keyset, keyid)
    key === nothing || return true
    refresh_for_key_miss!(keyset; observed_generation=generation)
    key, _ = jwkset_key_snapshot(keyset, keyid)
    return key !== nothing
end

function jwks_document(raw, url::String)
    if raw isa AbstractDict
        return raw
    elseif raw isa AbstractString
        return JSON.parse(String(raw))
    elseif raw isa AbstractVector{UInt8}
        return JSON.parse(String(raw))
    else
        throw(ArgumentError("unsupported JWKS document result from $url: $(typeof(raw))"))
    end
end

function fetch_url(url::String; downloader=nothing)
    if startswith(url, "file://")
        return readchomp(url[8:end])
    else
        output = PipeBuffer()
        response = Downloads.request(url; method="GET", output=output, downloader=downloader)
        # Downloads.request only throws on transport-level errors, not on HTTP error
        # status codes, so a 4xx/5xx error page would otherwise be parsed as a keyset.
        if response isa Downloads.Response && !(200 <= response.status < 300)
            throw(ErrorException("failed to fetch $url: HTTP status $(response.status)"))
        end
        return String(take!(output))
    end
end

function refresh!(
    keyseturl::String,
    keysetdict::Dict{String,JWK};
    default_algs=DEFAULT_JWK_ALGS,
    downloader=nothing,
    fetcher=nothing,
    allow_symmetric=nothing,
    required_operation::Union{Nothing,String}=nothing,
)
    raw = fetcher === nothing ? fetch_url(keyseturl; downloader=downloader) : fetcher(keyseturl)
    keys = jwks_document(raw, keyseturl)["keys"]
    allow_symmetric = something(allow_symmetric, !is_http_url(keyseturl))
    refresh!(
        keys,
        keysetdict;
        default_algs=default_algs,
        allow_symmetric=allow_symmetric,
        required_operation=required_operation,
    )
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

function jwk_operation_permissions(key)
    if haskey(key, "use")
        use = key["use"]
        use isa AbstractString && use == "sig" ||
            return (can_sign=false, can_verify=false)
    end
    haskey(key, "key_ops") ||
        return (can_sign=true, can_verify=true)
    key_ops = key["key_ops"]
    key_ops isa AbstractVector ||
        return (can_sign=false, can_verify=false)
    all(operation -> operation isa AbstractString, key_ops) ||
        return (can_sign=false, can_verify=false)
    return (
        can_sign="sign" in key_ops,
        can_verify="verify" in key_ops,
    )
end

function jwk_allows_operation(permissions, required_operation::Union{Nothing,String})
    if required_operation === nothing
        return permissions.can_sign || permissions.can_verify
    end
    required_operation == "sign" && return permissions.can_sign
    required_operation == "verify" && return permissions.can_verify
    return false
end

function refresh!(
    keys::Vector,
    keysetdict::Dict{String,JWK};
    default_algs=DEFAULT_JWK_ALGS,
    allow_symmetric::Bool=true,
    required_operation::Union{Nothing,String}=nothing,
)
    for key in keys
        kid = key["kid"]
        kty = key["kty"]
        alg = default_jwk_alg(key, default_algs)

        # ref: https://tools.ietf.org/html/rfc7518
        try
            permissions = jwk_operation_permissions(key)
            if !jwk_allows_operation(permissions, required_operation)
                @warn("key use or key_ops does not permit JWT $(something(required_operation, "signing or verification")), skipping key $kid")
                continue
            end
            if kty == "RSA"
                n = base64url_decode(key["n"])
                e = base64url_decode(key["e"])
                if alg in RSA_ALGORITHMS
                    keysetdict[kid] = JWKRSA(
                        alg,
                        rsa_public_key(n, e),
                        permissions.can_sign,
                        permissions.can_verify,
                    )
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "oct"
                if !allow_symmetric
                    @warn("symmetric keys are not accepted from this key source, skipping key $kid")
                    continue
                end
                k = base64url_decode(key["k"])
                if alg in HMAC_ALGORITHMS
                    keysetdict[kid] = JWKSymmetric(
                        alg,
                        k,
                        permissions.can_sign,
                        permissions.can_verify,
                    )
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "EC"
                crv = key["crv"]
                x = base64url_decode(key["x"])
                y = base64url_decode(key["y"])
                if alg in EC_ALGORITHMS
                    keysetdict[kid] = JWKEC(
                        alg,
                        ec_public_key(crv, x, y),
                        crv,
                        permissions.can_sign,
                        permissions.can_verify,
                    )
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "OKP"
                crv = key["crv"]
                x = base64url_decode(key["x"])
                if alg in OKP_ALGORITHMS
                    keysetdict[kid] = JWKOKP(
                        alg,
                        okp_public_key(crv, x),
                        crv,
                        permissions.can_sign,
                        permissions.can_verify,
                    )
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

const BASE64URL_ENCODE_TABLE = codeunits("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
const BASE64URL_INVALID = Int16(-1)

function base64url_value(c::UInt8)::Int16
    UInt8('A') <= c <= UInt8('Z') && return Int16(c - UInt8('A'))
    UInt8('a') <= c <= UInt8('z') && return Int16(c - UInt8('a') + 26)
    UInt8('0') <= c <= UInt8('9') && return Int16(c - UInt8('0') + 52)
    c == UInt8('-') && return Int16(62)
    c == UInt8('_') && return Int16(63)
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
    bytes = codeunits(data)
    byte_len = length(bytes)
    n = byte_len
    # Tolerate canonical trailing '=' padding, but reject excess or interior padding.
    padding_start = findfirst(==(UInt8('=')), bytes)
    if padding_start !== nothing
        for i in padding_start:byte_len
            bytes[i] == UInt8('=') || throw(ArgumentError("invalid base64url padding"))
        end
        n = padding_start - 1
        padding_count = byte_len - n
        remainder = n % 4
        expected_padding = remainder == 0 ? 0 : 4 - remainder
        padding_count == expected_padding || throw(ArgumentError("invalid base64url padding"))
    end
    out = UInt8[]
    sizehint!(out, (n * 3) >>> 2)
    buffer = UInt32(0)
    bits = 0
    @inbounds for i in 1:n
        value = base64url_value(bytes[i])
        value == BASE64URL_INVALID && throw(ArgumentError("invalid base64url character"))
        buffer = (buffer << 6) | UInt32(value)
        bits += 6
        if bits >= 8
            bits -= 8
            push!(out, UInt8((buffer >> bits) & 0xff))
        end
    end
    # A 6-bit remainder means length % 4 == 1, which cannot encode any byte.
    bits == 6 && throw(ArgumentError("invalid base64url length"))
    # The remaining 0/2/4 bits must be zero for a canonical base64url encoding.
    (buffer & ((UInt32(1) << bits) - UInt32(1))) == 0 || throw(ArgumentError("non-canonical base64url padding bits"))
    return out
end

"""
    with_valid_jwt(f, jwt, keyset; kid=nothing)

Run `f` with a valid JWT. The validated JWT is passed as an argument to `f`.
Signature failures raise `ArgumentError`; protected-header failures raise
[`JWTVerificationError`](@ref); time-claim failures raise [`JWTClaimError`](@ref).

Arguments:
- `f`: The function to execute with a valid JWT. The validated JWT is passed as an argument to `f`.
- `jwt`: The JWT string or JWT object to use. If a string is passed, it is converted to a JWT object.
- `keyset`: The JWKSet to use for validation. Only keys in this keyset are used for validation.

Keyword arguments:
- `kid`: The key id to use for validation. If not specified, the `kid` from the JWT header is used.
- `algorithms`: Ensure validation with one of the listed algorithms. Not enforced by default.
- `check_expiry`: Reject tokens whose `exp` has passed or whose `nbf` has not yet arrived
  (default `true`). Pass `false` to skip only these time checks.
- `leeway`: Seconds of clock skew tolerated on the time claims (default `0`).
- `now`: Current time in seconds since the epoch, or a zero-argument clock function.
  The default clock is sampled after signature validation.

An expired or not-yet-valid token raises [`JWTClaimError`](@ref); a token that fails
signature validation raises `ArgumentError`; and an unsupported protected header raises
[`JWTVerificationError`](@ref). For full claim validation — issuer, audience, `iat`/`max_age`,
and required claims — use [`verify`](@ref) with a [`Verifier`](@ref). Both modes reject
unsupported critical JOSE headers and unencoded payloads.
"""
function with_valid_jwt(f::Function, jwt::String, keyset::JWKSet;
    kid::Union{Nothing,String}=nothing,
    algorithms::Vector{String}=String[],
    check_expiry::Bool=true,
    leeway::Real=0,
    now=time,
)
    with_valid_jwt(f, JWT(jwt), keyset; kid=kid, algorithms=algorithms, check_expiry=check_expiry, leeway=leeway, now=now)
end
function with_valid_jwt(f::Function, jwt::JWT, keyset::JWKSet;
    kid::Union{Nothing,String}=nothing,
    algorithms::Vector{String}=String[],
    check_expiry::Bool=true,
    leeway::Real=0,
    now=time,
)
    header = try
        decode_jwt_json_object(jwt.header)
    catch
        throw(JWTVerificationError(
            :malformed_header,
            "jwt header is not valid base64url-encoded JSON"))
    end
    validate_claims_protected_header(header)

    if isnothing(kid)
        valid = validate!(jwt, keyset; algorithms=algorithms)
    else
        valid = validate!(jwt, keyset, kid; algorithms=algorithms)
    end

    valid || throw(ArgumentError("invalid jwt"))

    # A signature-valid token can still be expired. Callers of a function named
    # `with_valid_jwt` reasonably expect "valid" to include the time claims, so
    # enforce them here rather than handing back a token that expired long ago.
    if check_expiry
        claimset = try
            decode_jwt_json_object(jwt.payload)
        catch
            throw(JWTClaimError(:malformed_payload, "jwt payload must be a valid JSON object"))
        end
        now_value = now isa Real ? now : now()
        now_value isa Real || throw(ArgumentError("now must be a real number or return one"))
        check_time_claims(claimset; now=now_value, leeway=leeway)
    end

    return f(jwt)
end

include("remote_jwks.jl")
include("verifier.jl")

end # module JWTs
