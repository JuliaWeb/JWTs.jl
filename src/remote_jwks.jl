mutable struct RemoteJWKSet
    jwks_uri::String
    keyset::JWKSet
    ttl::Float64
    refresh_cooldown::Float64
    default_algs::Dict{String,String}
    fetcher::Function
    now::Function
    # `lock` protects timestamps and metadata. `refresh_lock` serializes I/O.
    lock::ReentrantLock
    refresh_lock::ReentrantLock
    fetched_at::Union{Nothing,Float64}
    last_failure_at::Union{Nothing,Float64}
    last_key_miss_refresh_at::Union{Nothing,Float64}
end

mutable struct OIDCDiscovery
    issuer::String
    discovery_uri::String
    metadata_ttl::Float64
    jwks_ttl::Float64
    refresh_cooldown::Float64
    default_algs::Dict{String,String}
    fetcher::Function
    now::Function
    lock::ReentrantLock
    refresh_lock::ReentrantLock
    jwks::Union{Nothing,RemoteJWKSet}
    fetched_at::Union{Nothing,Float64}
    last_failure_at::Union{Nothing,Float64}
    last_key_miss_refresh_at::Union{Nothing,Float64}
end

struct OIDCKeyGeneration
    source::Union{Nothing,RemoteJWKSet}
    generation::UInt64
end

function show(io::IO, jwks::RemoteJWKSet)
    key_count = lock(jwks.keyset.lock) do
        length(jwks.keyset.keys)
    end
    print(io, "RemoteJWKSet $key_count keys ($(jwks.jwks_uri))")
end

function show(io::IO, discovery::OIDCDiscovery)
    print(io, "OIDCDiscovery $(discovery.issuer) ($(discovery.discovery_uri))")
end

function normalize_cache_seconds(name::String, value::Real)
    return normalize_nonnegative_seconds(name, value)
end

function default_remote_fetcher(downloader)
    return url -> fetch_url(url; downloader=downloader)
end

normalize_fetcher_function(fetcher::Function) = fetcher
normalize_fetcher_function(fetcher) = url -> fetcher(url)

function RemoteJWKSet(
    jwks_uri::AbstractString;
    ttl::Real=300,
    refresh_cooldown::Real=30,
    default_algs=DEFAULT_JWK_ALGS,
    fetcher=nothing,
    downloader=nothing,
    now=monotonic_seconds,
)
    uri = String(jwks_uri)
    isempty(uri) && throw(ArgumentError("jwks_uri must not be empty"))
    keyset = JWKSet(
        uri;
        refresh_cooldown=refresh_cooldown,
        cache_now=now,
        default_algs=default_algs,
        fetcher=fetcher,
        downloader=downloader,
        allow_symmetric=false,
    )
    return RemoteJWKSet(
        uri,
        keyset,
        normalize_cache_seconds("ttl", ttl),
        normalize_cache_seconds("refresh_cooldown", refresh_cooldown),
        normalize_default_algs(default_algs),
        normalize_fetcher_function(fetcher === nothing ? default_remote_fetcher(downloader) : fetcher),
        normalize_now_function(now),
        ReentrantLock(),
        keyset.refresh_lock,
        nothing,
        nothing,
        nothing,
    )
end

function is_absolute_url(url::AbstractString)
    return occursin(r"^[A-Za-z][A-Za-z0-9+.-]*://", String(url))
end

function is_http_url(url::AbstractString)
    return occursin(r"^https?://"i, String(url))
end

function is_https_url(url::AbstractString)
    return occursin(r"^https://"i, String(url))
end

function is_oidc_issuer_url(url::AbstractString)
    value = String(url)
    match_result = match(r"^https://([^/?#]+)(/[^?#]*)?$"i, value)
    match_result === nothing && return false
    authority = match_result.captures[1]
    return !occursin('@', authority) && !any(isspace, value)
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
    fetcher=nothing,
    downloader=nothing,
    now=monotonic_seconds,
)
    issuer_s = String(issuer)
    isempty(issuer_s) && throw(ArgumentError("issuer must not be empty"))
    is_oidc_issuer_url(issuer_s) ||
        throw(ArgumentError("OIDC issuer must be an HTTPS URL without query or fragment"))
    discovery_uri = openid_configuration_url(issuer_s, discovery_path)
    is_https_url(discovery_uri) ||
        throw(ArgumentError("OIDC discovery URL must use HTTPS"))
    return OIDCDiscovery(
        issuer_s,
        discovery_uri,
        normalize_cache_seconds("metadata_ttl", metadata_ttl),
        normalize_cache_seconds("jwks_ttl", jwks_ttl),
        normalize_cache_seconds("refresh_cooldown", refresh_cooldown),
        normalize_default_algs(default_algs),
        normalize_fetcher_function(fetcher === nothing ? default_remote_fetcher(downloader) : fetcher),
        normalize_now_function(now),
        ReentrantLock(),
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
        nothing,
    )
end

function now_seconds(source)
    now_value = Float64(source.now())
    isfinite(now_value) || throw(ArgumentError("cache clock must return a finite number"))
    return now_value
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

function remote_jwks_snapshot(source::RemoteJWKSet, keyid::Union{Nothing,String}=nothing)
    return lock(source.lock) do
        lock(source.keyset.lock) do
            key = keyid === nothing ? nothing : get(source.keyset.keys, keyid, nothing)
            sole_kid = length(source.keyset.keys) == 1 ? first(keys(source.keyset.keys)) : nothing
            sole_key = sole_kid === nothing ? nothing : source.keyset.keys[sole_kid]
            return (
                key=key,
                sole_kid=sole_kid,
                sole_key=sole_key,
                generation=source.keyset.refresh_generation,
                key_count=length(source.keyset.keys),
                fetched_at=source.fetched_at,
                last_failure_at=source.last_failure_at,
                last_key_miss_refresh_at=source.last_key_miss_refresh_at,
            )
        end
    end
end

function install_remote_jwks!(
    source::RemoteJWKSet,
    keys::Dict{String,JWK},
    completed_at::Float64;
    record_key_miss::Bool,
)
    return lock(source.lock) do
        generation = lock(source.keyset.lock) do
            source.keyset.keys = keys
            source.keyset.refresh_generation += UInt64(1)
            source.keyset.refresh_generation
        end
        source.fetched_at = completed_at
        source.last_failure_at = nothing
        record_key_miss && (source.last_key_miss_refresh_at = completed_at)
        return generation
    end
end

# Caller holds `refresh_lock`. State locks are held only for snapshots and installs.
function refresh_remote_jwks_locked!(
    source::RemoteJWKSet;
    throw_if_empty::Bool,
    force::Bool=false,
    record_key_miss::Bool=false,
)
    started_at = now_seconds(source)
    state = remote_jwks_snapshot(source)
    if !force && in_cooldown(state.last_failure_at, started_at, source.refresh_cooldown)
        if throw_if_empty || state.key_count == 0
            throw(JWKSError(:jwks_refresh_cooldown, "JWKS refresh for $(source.jwks_uri) is in cooldown after a previous failure"))
        end
        return false
    end

    try
        doc = fetch_json_document(source.fetcher, source.jwks_uri)
        keys = Dict{String,JWK}()
        # A remote JWKS endpoint publishes only public keys; a symmetric ("oct") secret
        # arriving from one is a misconfiguration or attacker-controlled forge-able key.
        refresh!(
            jwks_keys(doc, source.jwks_uri),
            keys;
            default_algs=source.default_algs,
            allow_symmetric=false,
            required_operation="verify",
        )
        completed_at = now_seconds(source)
        lock(source.keyset.lock) do
            source.keyset.url = source.jwks_uri
        end
        install_remote_jwks!(source, keys, completed_at; record_key_miss=record_key_miss)
        return true
    catch
        completed_at = now_seconds(source)
        key_count = lock(source.lock) do
            source.last_failure_at = completed_at
            record_key_miss && (source.last_key_miss_refresh_at = completed_at)
            lock(source.keyset.lock) do
                length(source.keyset.keys)
            end
        end
        if throw_if_empty || key_count == 0
            throw(JWKSError(:jwks_refresh_failed, "failed to refresh JWKS from $(source.jwks_uri)"))
        end
        return false
    end
end

function ensure_remote_jwks!(
    source::RemoteJWKSet;
    wait_for_refresh::Bool,
)
    acquired = if wait_for_refresh
        lock(source.refresh_lock)
        true
    else
        trylock(source.refresh_lock)
    end
    acquired || return false
    try
        now_value = now_seconds(source)
        state = remote_jwks_snapshot(source)
        cache_expired(state.fetched_at, now_value, source.ttl) || return false
        return refresh_remote_jwks_locked!(
            source;
            throw_if_empty=state.key_count == 0,
        )
    finally
        unlock(source.refresh_lock)
    end
end

function refresh!(source::RemoteJWKSet)
    lock(source.refresh_lock)
    try
        refresh_remote_jwks_locked!(source; throw_if_empty=true, force=true)
    finally
        unlock(source.refresh_lock)
    end
    return nothing
end

function refresh_for_key_miss!(
    source::RemoteJWKSet;
    observed_generation::Union{Nothing,UInt64}=nothing,
)
    lock(source.refresh_lock)
    try
        now_value = now_seconds(source)
        state = remote_jwks_snapshot(source)
        observed_generation !== nothing &&
            state.generation != observed_generation && return true
        in_cooldown(
            state.last_key_miss_refresh_at,
            now_value,
            source.refresh_cooldown,
        ) && return false
        return refresh_remote_jwks_locked!(
            source;
            throw_if_empty=state.key_count == 0,
            record_key_miss=true,
        )
    finally
        unlock(source.refresh_lock)
    end
end

function resolve_verification_key_with_generation(keyset::JWKSet, keyid::String)
    key, generation = jwkset_key_snapshot(keyset, keyid)
    if key === nothing
        refresh_for_key_miss!(keyset; observed_generation=generation)
        key, generation = jwkset_key_snapshot(keyset, keyid)
    end
    key === nothing &&
        throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
    return key, generation
end

function resolve_verification_key_with_generation(source::RemoteJWKSet, keyid::String)
    now_value = now_seconds(source)
    state = remote_jwks_snapshot(source, keyid)
    expired = cache_expired(state.fetched_at, now_value, source.ttl)

    if state.key !== nothing && !expired
        return state.key, state.generation
    elseif expired
        # Missing keys wait for the single flight. A lookup that already has a stale
        # cached key may keep using it when another refresh is in progress.
        refreshed = ensure_remote_jwks!(
            source;
            wait_for_refresh=state.key === nothing,
        )
        after = remote_jwks_snapshot(source, keyid)
        if after.key !== nothing
            observation = refreshed || after.generation != state.generation ?
                state.generation : after.generation
            return after.key, observation
        end
        (refreshed || after.generation != state.generation) &&
            throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
        state.key === nothing || return state.key, state.generation
    end

    current = remote_jwks_snapshot(source, keyid)
    if current.key === nothing
        refresh_for_key_miss!(source; observed_generation=current.generation)
        current = remote_jwks_snapshot(source, keyid)
    end
    current.key === nothing &&
        throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
    return current.key, current.generation
end

function resolve_verification_key(keyset::JWKSet, keyid::String)
    key, _ = resolve_verification_key_with_generation(keyset, keyid)
    return key
end

function resolve_verification_key(source::RemoteJWKSet, keyid::String)
    key, _ = resolve_verification_key_with_generation(source, keyid)
    return key
end

function oidc_snapshot(source::OIDCDiscovery)
    return lock(source.lock) do
        return (
            jwks=source.jwks,
            fetched_at=source.fetched_at,
            last_failure_at=source.last_failure_at,
            last_key_miss_refresh_at=source.last_key_miss_refresh_at,
        )
    end
end

function oidc_key_generation(state)
    state.jwks === nothing && return OIDCKeyGeneration(nothing, UInt64(0))
    generation = remote_jwks_snapshot(state.jwks).generation
    return OIDCKeyGeneration(state.jwks, generation)
end

function oidc_cache_expired(source::OIDCDiscovery, state, now_value::Float64)
    state.jwks === nothing && return true
    cache_expired(state.fetched_at, now_value, source.metadata_ttl) && return true
    remote_state = remote_jwks_snapshot(state.jwks)
    return cache_expired(remote_state.fetched_at, now_value, source.jwks_ttl)
end

# Caller holds `source.refresh_lock`. Discovery and JWKS data are staged together,
# so a bad replacement endpoint cannot discard the last complete trust state.
function refresh_oidc_composite_locked!(source::OIDCDiscovery)
    state = oidc_snapshot(source)
    try
        metadata = fetch_json_document(source.fetcher, source.discovery_uri)
        metadata isa AbstractDict ||
            throw(JWKSError(:oidc_invalid, "OIDC discovery document must be a JSON object"))

        # The configured issuer and discovered issuer are identifiers, not URLs to
        # normalize. OpenID Connect Discovery requires exact string equality.
        discovered_issuer = get(metadata, "issuer", nothing)
        discovered_issuer isa AbstractString ||
            throw(JWKSError(:oidc_invalid, "OIDC discovery document is missing issuer"))
        String(discovered_issuer) == source.issuer ||
            throw(JWKSError(:oidc_issuer_mismatch, "OIDC discovery issuer does not match configured issuer"))

        jwks_uri = get(metadata, "jwks_uri", nothing)
        jwks_uri isa AbstractString ||
            throw(JWKSError(:oidc_invalid, "OIDC discovery document is missing jwks_uri"))
        uri = String(jwks_uri)
        isempty(uri) &&
            throw(JWKSError(:oidc_invalid, "OIDC discovery jwks_uri must not be empty"))
        is_https_url(uri) ||
            throw(JWKSError(:oidc_invalid, "OIDC discovery jwks_uri must use HTTPS"))

        # Always stage into a new source. Reusing the live source would expose its
        # new key generation before the metadata/JWKS pair is committed below.
        candidate = RemoteJWKSet(
            uri;
            ttl=source.jwks_ttl,
            refresh_cooldown=source.refresh_cooldown,
            default_algs=source.default_algs,
            fetcher=source.fetcher,
            now=source.now,
        )

        lock(candidate.refresh_lock)
        try
            # Force one selected-key fetch. The outer OIDC coordinator owns the
            # request budget, so the nested source must not apply a second cooldown.
            refresh_remote_jwks_locked!(
                candidate;
                throw_if_empty=true,
                force=true,
                record_key_miss=false,
            )
        finally
            unlock(candidate.refresh_lock)
        end

        completed_at = now_seconds(source)
        lock(source.lock) do
            source.jwks = candidate
            source.fetched_at = completed_at
            source.last_failure_at = nothing
        end
        return true
    catch
        completed_at = now_seconds(source)
        lock(source.lock) do
            source.last_failure_at = completed_at
        end
        current = oidc_snapshot(source).jwks
        cached_key_count = current === nothing ? 0 :
            remote_jwks_snapshot(current).key_count
        cached_key_count == 0 &&
            throw(JWKSError(:oidc_refresh_failed, "failed to refresh OIDC discovery and JWKS for $(source.issuer)"))
        return false
    end
end

function stamp_oidc_key_miss!(source::OIDCDiscovery)
    completed_at = now_seconds(source)
    lock(source.lock) do
        source.last_key_miss_refresh_at = completed_at
    end
    return nothing
end

function ensure_oidc_cache!(source::OIDCDiscovery)
    now_value = now_seconds(source)
    state = oidc_snapshot(source)
    oidc_cache_expired(source, state, now_value) || return false

    cached_key_count = state.jwks === nothing ? 0 :
        remote_jwks_snapshot(state.jwks).key_count
    if in_cooldown(
            state.last_failure_at,
            now_value,
            source.refresh_cooldown,
        )
        cached_key_count == 0 &&
            throw(JWKSError(:oidc_refresh_cooldown, "OIDC refresh for $(source.issuer) is in cooldown"))
        return false
    end

    acquired = if state.jwks === nothing
        lock(source.refresh_lock)
        true
    else
        trylock(source.refresh_lock)
    end
    acquired || return false
    try
        now_value = now_seconds(source)
        state = oidc_snapshot(source)
        oidc_cache_expired(source, state, now_value) || return true
        cached_key_count = state.jwks === nothing ? 0 :
            remote_jwks_snapshot(state.jwks).key_count
        if in_cooldown(
                state.last_failure_at,
                now_value,
                source.refresh_cooldown,
            )
            cached_key_count == 0 &&
                throw(JWKSError(:oidc_refresh_cooldown, "OIDC refresh for $(source.issuer) is in cooldown"))
            return false
        end
        return refresh_oidc_composite_locked!(source)
    finally
        unlock(source.refresh_lock)
    end
end

function oidc_jwks_source_with_generation!(source::OIDCDiscovery)
    before = oidc_snapshot(source)
    before_generation = oidc_key_generation(before)
    ensure_oidc_cache!(source)
    after = oidc_snapshot(source)
    after.jwks === nothing &&
        throw(JWKSError(:oidc_invalid, "OIDC discovery did not provide a JWKS source"))
    after_generation = oidc_key_generation(after)
    observation = if before_generation.source !== after_generation.source ||
            before_generation.generation != after_generation.generation
        before_generation
    else
        after_generation
    end
    return after.jwks, observation
end

function oidc_jwks_source!(source::OIDCDiscovery)
    jwks, _ = oidc_jwks_source_with_generation!(source)
    return jwks
end

function resolve_verification_key_with_generation(source::OIDCDiscovery, keyid::String)
    jwks, observation = oidc_jwks_source_with_generation!(source)
    state = remote_jwks_snapshot(jwks, keyid)
    if state.key === nothing
        refresh_for_key_miss!(
            source;
            observed_generation=observation,
        )
        jwks, observation = oidc_jwks_source_with_generation!(source)
        state = remote_jwks_snapshot(jwks, keyid)
    end
    state.key === nothing &&
        throw(JWKSError(:key_not_found, "JWK set does not contain key id $keyid"))
    return state.key, observation
end

function resolve_verification_key(source::OIDCDiscovery, keyid::String)
    key, _ = resolve_verification_key_with_generation(source, keyid)
    return key
end

# RFC 7515 Section 4.1.4 makes `kid` optional, and issuers publishing a single
# signing key routinely omit it. When the key set is unambiguous there is exactly
# one key it could have been signed with, so use it; otherwise the token must say.
function require_sole_verification_key(keyid, key, generation::UInt64, key_count::Int)
    key_count == 1 || throw(JWTVerificationError(
        :key_id_missing,
        "jwt header does not include kid and the key set has $key_count keys"))
    return keyid::String, key::JWK, generation
end

function resolve_sole_verification_key_with_generation(keyset::JWKSet)
    keyid, key, generation, key_count, url = jwkset_sole_snapshot(keyset)
    if key_count != 1 && !isempty(url)
        refresh_for_key_miss!(keyset; observed_generation=generation)
        keyid, key, generation, key_count, _ = jwkset_sole_snapshot(keyset)
    end
    return require_sole_verification_key(keyid, key, generation, key_count)
end

function resolve_sole_verification_key_with_generation(source::RemoteJWKSet)
    now_value = now_seconds(source)
    state = remote_jwks_snapshot(source)
    expired = cache_expired(state.fetched_at, now_value, source.ttl)

    if state.key_count == 1 && !expired
        return require_sole_verification_key(
            state.sole_kid,
            state.sole_key,
            state.generation,
            state.key_count,
        )
    elseif expired
        refreshed = ensure_remote_jwks!(
            source;
            wait_for_refresh=state.key_count == 0,
        )
        after = remote_jwks_snapshot(source)
        if after.key_count == 1
            observation = refreshed || after.generation != state.generation ?
                state.generation : after.generation
            return require_sole_verification_key(
                after.sole_kid,
                after.sole_key,
                observation,
                after.key_count,
            )
        end
        (refreshed || after.generation != state.generation) &&
            return require_sole_verification_key(
                after.sole_kid,
                after.sole_key,
                after.generation,
                after.key_count,
            )
    end

    current = remote_jwks_snapshot(source)
    if current.key_count != 1
        refresh_for_key_miss!(source; observed_generation=current.generation)
        current = remote_jwks_snapshot(source)
    end
    return require_sole_verification_key(
        current.sole_kid,
        current.sole_key,
        current.generation,
        current.key_count,
    )
end

function resolve_sole_verification_key_with_generation(source::OIDCDiscovery)
    jwks, observation = oidc_jwks_source_with_generation!(source)
    state = remote_jwks_snapshot(jwks)
    if state.key_count != 1
        refresh_for_key_miss!(
            source;
            observed_generation=observation,
        )
        jwks, observation = oidc_jwks_source_with_generation!(source)
        state = remote_jwks_snapshot(jwks)
    end
    keyid, key, _ = require_sole_verification_key(
        state.sole_kid,
        state.sole_key,
        state.generation,
        state.key_count,
    )
    return keyid, key, observation
end

function resolve_sole_verification_key(source)
    keyid, key, _ = resolve_sole_verification_key_with_generation(source)
    return keyid, key
end

function refresh_for_key_miss!(
    source::OIDCDiscovery;
    observed_generation=nothing,
)
    lock(source.refresh_lock)
    try
        now_value = now_seconds(source)
        state = oidc_snapshot(source)
        if observed_generation isa OIDCKeyGeneration
            current = state.jwks
            current_generation = current === nothing ? UInt64(0) :
                remote_jwks_snapshot(current).generation
            if current !== observed_generation.source ||
                    current_generation != observed_generation.generation
                return true
            end
        elseif observed_generation !== nothing
            throw(ArgumentError("invalid OIDC refresh observation"))
        end
        in_cooldown(
            state.last_key_miss_refresh_at,
            now_value,
            source.refresh_cooldown,
        ) && return false
        in_cooldown(
            state.last_failure_at,
            now_value,
            source.refresh_cooldown,
        ) && return false

        try
            return refresh_oidc_composite_locked!(source)
        finally
            stamp_oidc_key_miss!(source)
        end
    finally
        unlock(source.refresh_lock)
    end
end
