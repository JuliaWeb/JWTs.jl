mutable struct RemoteJWKSet{F,N}
    jwks_uri::String
    keyset::JWKSet
    ttl::Float64
    refresh_cooldown::Float64
    default_algs::Dict{String,String}
    fetcher::F
    now::N
    lock::ReentrantLock
    fetched_at::Union{Nothing,Float64}
    last_failure_at::Union{Nothing,Float64}
    last_unknown_refresh_at::Union{Nothing,Float64}
end

mutable struct OIDCDiscovery{F,N}
    issuer::String
    discovery_uri::String
    metadata_ttl::Float64
    jwks_ttl::Float64
    refresh_cooldown::Float64
    default_algs::Dict{String,String}
    fetcher::F
    now::N
    lock::ReentrantLock
    jwks::Union{Nothing,RemoteJWKSet{F,N}}
    fetched_at::Union{Nothing,Float64}
    last_failure_at::Union{Nothing,Float64}
end

const DEFAULT_JWK_ALGS = Dict("RSA" => "RS256", "oct" => "HS256")

function show(io::IO, jwks::RemoteJWKSet)
    print(io, "RemoteJWKSet $(length(jwks.keyset.keys)) keys ($(jwks.jwks_uri))")
end

function show(io::IO, discovery::OIDCDiscovery)
    print(io, "OIDCDiscovery $(discovery.issuer) ($(discovery.discovery_uri))")
end

function normalize_default_algs(default_algs)
    return Dict{String,String}(String(k) => String(v) for (k, v) in default_algs)
end

function normalize_cache_seconds(name::String, value::Real)
    value < 0 && throw(ArgumentError("$name must be non-negative"))
    return Float64(value)
end

function default_remote_fetcher(downloader)
    return url -> fetch_url(url; downloader=downloader)
end

function RemoteJWKSet(
    jwks_uri::AbstractString;
    ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher::F=nothing,
    downloader::D=nothing,
    now::N=time,
) where {F,D,N}
    uri = String(jwks_uri)
    isempty(uri) && throw(ArgumentError("jwks_uri must not be empty"))
    return RemoteJWKSet(
        uri,
        JWKSet(uri),
        normalize_cache_seconds("ttl", ttl),
        normalize_cache_seconds("refresh_cooldown", refresh_cooldown),
        normalize_default_algs(default_algs),
        fetcher === nothing ? default_remote_fetcher(downloader) : fetcher,
        now,
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
    )
end

function is_absolute_url(url::AbstractString)
    return occursin(r"^[A-Za-z][A-Za-z0-9+.-]*://", String(url))
end

function openid_configuration_url(issuer::AbstractString, discovery_path::AbstractString="/.well-known/openid-configuration")
    path = String(discovery_path)
    is_absolute_url(path) && return path
    base = rstrip(String(issuer), '/')
    suffix = startswith(path, "/") ? path : "/" * path
    return base * suffix
end

function OIDCDiscovery(
    issuer::AbstractString;
    discovery_path::AbstractString="/.well-known/openid-configuration",
    metadata_ttl::Real=300,
    jwks_ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher::F=nothing,
    downloader::D=nothing,
    now::N=time,
) where {F,D,N}
    issuer_s = String(rstrip(String(issuer), '/'))
    isempty(issuer_s) && throw(ArgumentError("issuer must not be empty"))
    return OIDCDiscovery(
        issuer_s,
        openid_configuration_url(issuer_s, discovery_path),
        normalize_cache_seconds("metadata_ttl", metadata_ttl),
        normalize_cache_seconds("jwks_ttl", jwks_ttl),
        normalize_cache_seconds("refresh_cooldown", refresh_cooldown),
        normalize_default_algs(default_algs),
        fetcher === nothing ? default_remote_fetcher(downloader) : fetcher,
        now,
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
    )
end

function now_seconds(source)
    return Float64(source.now())
end

function fetch_json_document(fetcher, url::String)
    raw = try
        fetcher(url)
    catch
        throw(JWKSError(:fetch_failed, "failed to fetch JSON document from $url"))
    end

    if raw isa AbstractDict
        return raw
    elseif raw isa AbstractString
        try
            return JSON.parse(String(raw))
        catch
            throw(JWKSError(:parse_failed, "failed to parse JSON document from $url"))
        end
    elseif raw isa AbstractVector{UInt8}
        try
            return JSON.parse(String(raw))
        catch
            throw(JWKSError(:parse_failed, "failed to parse JSON document from $url"))
        end
    else
        throw(JWKSError(:fetch_result_unsupported, "fetcher for $url returned unsupported type $(typeof(raw))"))
    end
end

function jwks_keys(doc, url::String)
    doc isa AbstractDict || throw(JWKSError(:jwks_invalid, "JWKS document from $url must be a JSON object"))
    keys = get(doc, "keys", nothing)
    keys isa AbstractVector || throw(JWKSError(:jwks_invalid, "JWKS document from $url is missing a keys array"))
    return keys
end

function in_cooldown(last_at::Union{Nothing,Float64}, now_value::Float64, cooldown::Float64)
    last_at === nothing && return false
    return now_value - last_at < cooldown
end

function refresh_remote_jwks_unlocked!(source::RemoteJWKSet, now_value::Float64; throw_if_empty::Bool)
    if in_cooldown(source.last_failure_at, now_value, source.refresh_cooldown)
        if throw_if_empty || isempty(source.keyset.keys)
            throw(JWKSError(:jwks_refresh_cooldown, "JWKS refresh for $(source.jwks_uri) is in cooldown after a previous failure"))
        end
        return false
    end

    try
        doc = fetch_json_document(source.fetcher, source.jwks_uri)
        keys = Dict{String,JWK}()
        refresh!(jwks_keys(doc, source.jwks_uri), keys; default_algs=source.default_algs)
        source.keyset.keys = keys
        source.keyset.url = source.jwks_uri
        source.fetched_at = now_value
        source.last_failure_at = nothing
        return true
    catch
        source.last_failure_at = now_value
        if throw_if_empty || isempty(source.keyset.keys)
            throw(JWKSError(:jwks_refresh_failed, "failed to refresh JWKS from $(source.jwks_uri)"))
        end
        return false
    end
end

function ensure_remote_jwks_unlocked!(source::RemoteJWKSet, now_value::Float64)
    if source.fetched_at === nothing
        refresh_remote_jwks_unlocked!(source, now_value; throw_if_empty=true)
    elseif now_value - source.fetched_at >= source.ttl
        refresh_remote_jwks_unlocked!(source, now_value; throw_if_empty=false)
    end
    return nothing
end

function refresh!(source::RemoteJWKSet)
    lock(source.lock)
    try
        refresh_remote_jwks_unlocked!(source, now_seconds(source); throw_if_empty=true)
    finally
        unlock(source.lock)
    end
    return nothing
end

function resolve_verification_key(keyset::JWKSet, keyid::String)
    haskey(keyset.keys, keyid) || refresh!(keyset)
    haskey(keyset.keys, keyid) || throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
    return keyset.keys[keyid]
end

function resolve_verification_key(source::RemoteJWKSet, keyid::String)
    lock(source.lock)
    try
        now_value = now_seconds(source)
        ensure_remote_jwks_unlocked!(source, now_value)
        if !haskey(source.keyset.keys, keyid) &&
                !in_cooldown(source.last_unknown_refresh_at, now_value, source.refresh_cooldown)
            source.last_unknown_refresh_at = now_value
            refresh_remote_jwks_unlocked!(source, now_value; throw_if_empty=false)
        end
        haskey(source.keyset.keys, keyid) || throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
        return source.keyset.keys[keyid]
    finally
        unlock(source.lock)
    end
end

function refresh_oidc_discovery_unlocked!(source::OIDCDiscovery, now_value::Float64; throw_if_empty::Bool)
    if in_cooldown(source.last_failure_at, now_value, source.refresh_cooldown)
        if throw_if_empty || source.jwks === nothing
            throw(JWKSError(:oidc_refresh_cooldown, "OIDC discovery refresh for $(source.issuer) is in cooldown after a previous failure"))
        end
        return false
    end

    try
        metadata = fetch_json_document(source.fetcher, source.discovery_uri)
        metadata isa AbstractDict || throw(JWKSError(:oidc_invalid, "OIDC discovery document must be a JSON object"))
        discovered_issuer = get(metadata, "issuer", source.issuer)
        discovered_issuer isa AbstractString || throw(JWKSError(:oidc_invalid, "OIDC discovery issuer must be a string"))
        rstrip(String(discovered_issuer), '/') == source.issuer ||
            throw(JWKSError(:oidc_issuer_mismatch, "OIDC discovery issuer does not match configured issuer"))
        jwks_uri = get(metadata, "jwks_uri", nothing)
        jwks_uri isa AbstractString || throw(JWKSError(:oidc_invalid, "OIDC discovery document is missing jwks_uri"))
        isempty(jwks_uri) && throw(JWKSError(:oidc_invalid, "OIDC discovery jwks_uri must not be empty"))
        if source.jwks === nothing || source.jwks.jwks_uri != String(jwks_uri)
            source.jwks = RemoteJWKSet(
                jwks_uri;
                ttl=source.jwks_ttl,
                refresh_cooldown=source.refresh_cooldown,
                default_algs=source.default_algs,
                fetcher=source.fetcher,
                now=source.now,
            )
        end
        source.fetched_at = now_value
        source.last_failure_at = nothing
        return true
    catch
        source.last_failure_at = now_value
        if throw_if_empty || source.jwks === nothing
            throw(JWKSError(:oidc_refresh_failed, "failed to refresh OIDC discovery from $(source.discovery_uri)"))
        end
        return false
    end
end

function oidc_jwks_source!(source::OIDCDiscovery)
    lock(source.lock)
    try
        now_value = now_seconds(source)
        if source.jwks === nothing
            refresh_oidc_discovery_unlocked!(source, now_value; throw_if_empty=true)
        elseif source.fetched_at === nothing || now_value - source.fetched_at >= source.metadata_ttl
            refresh_oidc_discovery_unlocked!(source, now_value; throw_if_empty=false)
        end
        source.jwks === nothing && throw(JWKSError(:oidc_invalid, "OIDC discovery did not provide a JWKS source"))
        return source.jwks
    finally
        unlock(source.lock)
    end
end

function resolve_verification_key(source::OIDCDiscovery, keyid::String)
    return resolve_verification_key(oidc_jwks_source!(source), keyid)
end
