using JWTs
using JWTs: JWT, JWK, JWKSet, JWKRSA, JWKSymmetric
using JWTs: Verifier, claims, issigned, isverified, kid, refresh!, sign!, validate!, verify, with_valid_jwt
using Test
using JSON

const PUBLIC_NAMES = (
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
)

@testset "public API surface" begin
    @test all(name -> !Base.isexported(JWTs, name), PUBLIC_NAMES)
    @test !Base.isexported(JWTs, :show)
    if isdefined(Base, :ispublic)
        @test all(name -> Base.ispublic(JWTs, name), PUBLIC_NAMES)
        @test !Base.ispublic(JWTs, :show)
    end
end

const test_payload_data = [
    JSON.parse("""{
        "jti": "0b821616-0a5f-47f3-af00-8caf03619303",
        "exp": 1543351759,
        "nbf": 0,
        "iat": 1543315759,
        "iss": "https://example.com/auth/",
        "aud": "portal",
        "sub": "b1df5448-a16b-4a13-b03b-2213d56ea1b5",
        "typ": "Bearer",
        "azp": "portal",
        "auth_time": 1543315759,
        "session_state": "f196425d-226b-4e6d-bc81-feecb276f424",
        "acr": "1",
        "allowed-origins": [ "" ],
        "realm_access": { "roles": [ "uma_authorization" ] },
        "resource_access": {
            "broker": { "roles": [ "read-token" ] },
            "account": { "roles": [ "manage-account", "manage-account-links", "view-profile" ] }
        },
        "preferred_username": "chhhhhhhhhhhhhhhhhhhhhhhhhaaaaaaaaaaaaabbb"
    }"""),
    JSON.parse("""{
        "iss": "https://auth2.juliacomputing.io/dex",
        "sub": "ChUxjfgsajfurjsjdut0483672kdhgstgy283jssZQ",
        "aud": "example-audience",
        "exp": 1536080651,
        "iat": 1535994251,
        "nonce": "1777777777777aaaaaaaaabbbbbbbbbb",
        "at_hash": "222222-G-JJJJJJJJJJJJJ",
        "email": "user@example.com",
        "email_verified": true,
        "name": "Example User"
    }""")
]

function print_header(msg)
    println("")
    println("-"^60)
    println(msg)
    println("-"^60)
end

include("trim_compile_tests.jl")

function test_and_get_keyset(url)
    print_header("keyset: $url")

    keyset = JWKSet(url)
    @test length(keyset.keys) == 0

    refresh!(keyset)
    @test length(keyset.keys) > 0
    for (k,v) in keyset.keys
        println("    ", k, " => ", v.key)
    end

    keyset
end

function test_in_mem_keyset(template)
    print_header("keyset: $template")
    keyset = JWKSet(JSON.parse(read(template, String))["keys"])
    @test length(keyset.keys) == 4
    for (k,v) in keyset.keys
        println("    ", k, " => ", v.key)
    end
end

function tamper_signature(jwt::JWT)
    sig = JWTs.base64url_decode(jwt.signature)
    sig[1] = xor(sig[1], 0x01)
    JWT(; jwt=join([jwt.header, jwt.payload, JWTs.base64url_encode(sig)], "."))
end

mutable struct TestClock
    value::Float64
end
(clock::TestClock)() = clock.value

function signing_jwk(public_jwk, keyfile)
    key = JWTs.parse_keyfile(keyfile)
    if public_jwk isa JWKRSA
        return JWKRSA(JWTs.alg(public_jwk), key)
    elseif public_jwk isa JWTs.JWKEC
        return JWTs.JWKEC(JWTs.alg(public_jwk), key, public_jwk.crv)
    elseif public_jwk isa JWTs.JWKOKP
        return JWTs.JWKOKP(JWTs.alg(public_jwk), key, public_jwk.crv)
    else
        throw(ArgumentError("unsupported asymmetric JWK type $(typeof(public_jwk))"))
    end
end

function jwks_doc_with_kids(path, wanted_kids)
    doc = JSON.parse(read(path, String))
    wanted = Set(wanted_kids)
    return Dict("keys" => [key for key in doc["keys"] if key["kid"] in wanted])
end

function signing_keyset_from_jwks_doc(doc, keydir)
    keyset = JWKSet(doc["keys"])
    signingkeyset = deepcopy(keyset)
    for (k, public_jwk) in collect(signingkeyset.keys)
        signingkeyset.keys[k] = signing_jwk(public_jwk, joinpath(keydir, "$k.private.pem"))
    end
    return signingkeyset
end

function signed_with_key(signingkeyset, signing_kid, header_kid, payload)
    jwt = JWT(; payload=payload)
    sign!(jwt, signingkeyset.keys[signing_kid], header_kid)
    return jwt
end

function signed_with_header(key, payload, header)
    unsigned = JWT(; payload=payload)
    encoded_header = JWTs.base64url_encode(JSON.json(header))
    signature = JWTs.base64url_encode(
        JWTs.signbytes(key, encoded_header * "." * unsigned.payload))
    return JWT(; jwt=join((encoded_header, unsigned.payload, signature), "."))
end

function test_signing_keys(keyset, signingkeyset, algorithms::Vector{String})
    for k in keys(keyset.keys)
        for d in test_payload_data
            jwt = JWT(; payload=d)
            @test claims(jwt) == d
            @test_throws ArgumentError JWTs.alg(jwt)
            @test_throws ArgumentError kid(jwt)
            @test !issigned(jwt)
            sign!(jwt, signingkeyset, k)
            @test issigned(jwt)
            @test isvalid(jwt)
            @test isverified(jwt)
            @test claims(jwt) == d
            original_payload = jwt.payload
            original_header = jwt.header
            original_signature = jwt.signature
            jwt.payload = original_payload
            @test jwt.payload == original_payload
            @test jwt.header == original_header
            @test jwt.signature == original_signature
            @test !isverified(jwt)
            @test isvalid(jwt) === nothing
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            jwt.header = original_header
            @test jwt.header == original_header
            @test !isverified(jwt)
            @test isvalid(jwt) === nothing
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            jwt.signature = original_signature
            @test jwt.signature == original_signature
            @test !isverified(jwt)
            @test isvalid(jwt) === nothing
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            @test_throws ArgumentError setproperty!(jwt, :verified, true)
            @test_throws ArgumentError setproperty!(jwt, :valid, true)
            @test_throws ArgumentError setproperty!(jwt, :payload, nothing)
            @test_throws ArgumentError setproperty!(jwt, :header, 1)
            @test JWTs.alg(jwt) == JWTs.alg(keyset.keys[k])
            @test kid(jwt) == k
            header = JWTs.decodepart(jwt.header)
            @test header == Dict("alg" => JWTs.alg(keyset.keys[k]), "kid" => k, "typ" => "JWT")

            println("    JWT: ", jwt)
            jwt2 = JWT(; jwt=string(jwt))
            @test claims(jwt2) == claims(jwt)
            @test JWTs.alg(jwt2) == JWTs.alg(jwt)
            @test kid(jwt2) == kid(jwt)
            @test JWTs.decodepart(jwt2.header) == JWTs.decodepart(jwt.header)
            @test issigned(jwt2)
            @test !isverified(jwt2)
            @test isvalid(jwt2) === nothing
            # test with valid algos
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            @test !validate!(jwt, keyset, k; algorithms=["invalidalgo"])
            @test isverified(jwt)
            @test !isvalid(jwt)
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            @test !validate!(tamper_signature(jwt), keyset, k; algorithms=algorithms)

            # test with invalid algos
            jwt_check = JWT(; jwt=string(jwt))
            @test !validate!(jwt_check, keyset, k; algorithms=["invalidalgo"])

            # test without specifying algos
            jwt_check = JWT(; jwt=string(jwt))
            @test validate!(jwt_check, keyset, k; algorithms=String[])

            @test issigned(jwt)
            @test isvalid(jwt)
            @test isverified(jwt)

            jwt2 = JWT(; jwt=string(jwt))
            @test claims(jwt2) == claims(jwt)
            @test JWTs.alg(jwt2) == JWTs.alg(jwt)
            @test kid(jwt2) == kid(jwt)
            @test JWTs.decodepart(jwt2.header) == JWTs.decodepart(jwt.header)
            @test issigned(jwt2)
            @test !isverified(jwt2)
            @test isvalid(jwt2) === nothing
            invalidkey = findfirst(x -> x != keyset.keys[k], keyset.keys)
            @test !validate!(jwt2, keyset, invalidkey; algorithms=algorithms)
            @test issigned(jwt2)
            @test !isvalid(jwt2)
            @test isverified(jwt2)
            @test validate!(jwt, keyset, k; algorithms=algorithms)
            @test !validate!(jwt, keyset, invalidkey; algorithms=algorithms)
            @test validate!(jwt, keyset, k; algorithms=algorithms)

            same_alg_invalidkey = findfirst(x -> x != keyset.keys[k] && JWTs.alg(x) == JWTs.alg(keyset.keys[k]), keyset.keys)
            if same_alg_invalidkey !== nothing
                jwt3 = JWT(; jwt=string(jwt))
                @test !validate!(jwt3, keyset, same_alg_invalidkey; algorithms=[JWTs.alg(keyset.keys[k])])
                @test isverified(jwt3)
                @test !isvalid(jwt3)
            end
        end
    end
end

function test_signing_asymmetric_keys(keyset_url, algorithms::Vector{String})
    print_header("signing asymmetric keys")
    keyset = JWKSet(keyset_url)
    refresh!(keyset)
    signingkeyset = deepcopy(keyset)
    for k in keys(signingkeyset.keys)
        keyfile = joinpath(dirname(keyset_url), "$k.private.pem")
        if startswith(keyfile, "file://")
            keyfile = keyfile[8:end]
        end
        signingkeyset.keys[k] = signing_jwk(signingkeyset.keys[k], keyfile)
    end
    test_signing_keys(keyset, signingkeyset, algorithms)
end

function test_signing_symmetric_keys(keyset_url, algorithms::Vector{String})
    print_header("signing symmetric keys")
    keyset = test_and_get_keyset(keyset_url)
    test_signing_keys(keyset, keyset, algorithms)
end

function test_with_valid_jwt(keyset_url, algorithms::Vector{String})
    print_header("with_valid_jwt do block")

    keyset = JWKSet(keyset_url)
    refresh!(keyset)

    d = test_payload_data[1]
    jwt = JWT(; payload=d)
    key = first(keys(keyset.keys))
    sign!(jwt, keyset, key)

    # The fixture payloads carry `exp` values from 2018, so these calls exercise the
    # do-block plumbing with expiry checking switched off. Expiry enforcement itself
    # is covered by the "with_valid_jwt expiry" testset.
    with_valid_jwt(jwt, keyset; algorithms=algorithms, check_expiry=false) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end

    jwt2 = JWT(; jwt=string(jwt))
    with_valid_jwt(jwt2, keyset; check_expiry=false) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
    with_valid_jwt(string(jwt), keyset; kid=key, check_expiry=false) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
    with_valid_jwt(jwt2, keyset; kid=key, check_expiry=false) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
    @test_throws ArgumentError with_valid_jwt(identity, JWT(; jwt=string(jwt)), keyset; kid=key, algorithms=["invalidalgo"])
end

function test_validation_state_safety(keyset_url)
    print_header("validation state safety")

    keyset = JWKSet(keyset_url)
    refresh!(keyset)
    hs256_keyids = [k for (k, v) in keyset.keys if JWTs.alg(v) == "HS256"]
    @test length(hs256_keyids) >= 2
    keyid = hs256_keyids[1]
    other_keyid = hs256_keyids[2]
    key = keyset.keys[keyid]
    payload = Dict("sub" => "state-test", "iat" => 1)

    jwt = JWT(; payload=payload)
    sign!(jwt, keyset, keyid)
    @test validate!(jwt, keyset, keyid; algorithms=[JWTs.alg(key)])
    @test !validate!(jwt, keyset, keyid; algorithms=["invalidalgo"])
    @test validate!(jwt, keyset, keyid; algorithms=[JWTs.alg(key)])

    @test !validate!(jwt, keyset, other_keyid; algorithms=[JWTs.alg(key)])
    @test validate!(jwt, keyset, keyid; algorithms=[JWTs.alg(key)])

    header_without_alg_or_kid = JWTs.base64url_encode(JSON.json(Dict("typ" => "JWT")))
    missing_header_token = JWT(; jwt=join([header_without_alg_or_kid, jwt.payload, jwt.signature], "."))
    @test JWTs.alg(missing_header_token) === nothing
    @test kid(missing_header_token) === nothing
    @test !validate!(missing_header_token, key; algorithms=[JWTs.alg(key)])
    @test_throws ArgumentError validate!(missing_header_token, keyset; algorithms=[JWTs.alg(key)])

    header_with_extensions = JWTs.base64url_encode(JSON.json(Dict{String,Any}(
        "alg" => JWTs.alg(key),
        "kid" => keyid,
        "typ" => "JWT",
        "crit" => ["exp"],
        "nested" => Dict("accepted" => true),
    )))
    extended_header_token = JWT(; jwt=join([header_with_extensions, jwt.payload, jwt.signature], "."))
    @test JWTs.alg(extended_header_token) == JWTs.alg(key)
    @test kid(extended_header_token) == keyid

    trailing_header_data = JWTs.base64url_encode("""{"alg":"$(JWTs.alg(key))","kid":"$keyid"} false""")
    trailing_header_token = JWT(; jwt=join([trailing_header_data, jwt.payload, jwt.signature], "."))
    @test_throws ArgumentError JWTs.alg(trailing_header_token)
    @test_throws ArgumentError kid(trailing_header_token)

    malformed = JWT(; jwt="not-a-valid-compact-token")
    @test !issigned(malformed)
    @test isverified(malformed)
    @test isvalid(malformed) === false
    @test_throws ArgumentError validate!(malformed, key; algorithms=[JWTs.alg(key)])
end

function test_verifier_claims(keyset_url)
    print_header("verifier claims")

    keyset = JWKSet(keyset_url)
    refresh!(keyset)
    keyid = first(k for (k, v) in keyset.keys if JWTs.alg(v) == "HS256")
    algorithm = JWTs.alg(keyset.keys[keyid])

    function signed(payload)
        jwt = JWT(; payload=payload)
        sign!(jwt, keyset, keyid)
        return jwt
    end

    base_payload = Dict{String,Any}(
        "iss" => "https://issuer.example",
        "sub" => "subject-1",
        "aud" => ["api://default", "web-client"],
        "exp" => 1100,
        "nbf" => 900,
        "iat" => 950,
        "jti" => "token-1",
        "nonce" => "nonce-1",
    )
    jwt = signed(base_payload)
    verifier = Verifier(
        keyset;
        algorithms=[algorithm],
        issuer="https://issuer.example",
        audience="api://default",
        subject="subject-1",
        jwtid="token-1",
        nonce="nonce-1",
        required_claims=["exp", "nbf", "iat"],
        now=() -> 1000.0,
    )

    verified = verify(verifier, string(jwt))
    @test verified.token isa JWT
    @test verified.header["typ"] == "JWT"
    @test JWTs.claims(verified) == base_payload
    @test JWTs.kid(verified) == keyid
    @test JWTs.alg(verified) == algorithm
    @test verified.key === keyset.keys[keyid]
    @test verify(verifier, jwt).claims == base_payload

    vector_audience_verifier = Verifier(keyset; algorithms=[algorithm], audience=["mobile-client", "web-client"], now=() -> 1000.0)
    @test verify(vector_audience_verifier, signed(base_payload)).claims == base_payload

    string_audience_payload = copy(base_payload)
    string_audience_payload["aud"] = "api://default"
    @test verify(verifier, signed(string_audience_payload)).claims == string_audience_payload

    @test_throws ArgumentError Verifier(keyset)
    @test_throws ArgumentError Verifier(keyset; algorithms=String[])
    @test_throws ArgumentError Verifier(keyset; algorithms=["none"])
    @test_throws JWTs.JWTVerificationError verify(Verifier(keyset; algorithms=["HS384"], now=() -> 1000.0), string(jwt))
    @test_throws JWTs.JWTVerificationError verify(verifier, tamper_signature(jwt))

    wrong_issuer = Verifier(keyset; algorithms=[algorithm], issuer="https://wrong.example", now=() -> 1000.0)
    @test_throws JWTs.JWTClaimError verify(wrong_issuer, signed(base_payload))

    wrong_audience = Verifier(keyset; algorithms=[algorithm], audience="other-audience", now=() -> 1000.0)
    @test_throws JWTs.JWTClaimError verify(wrong_audience, signed(base_payload))

    wrong_subject = Verifier(keyset; algorithms=[algorithm], subject="subject-2", now=() -> 1000.0)
    @test_throws JWTs.JWTClaimError verify(wrong_subject, signed(base_payload))

    wrong_jti = Verifier(keyset; algorithms=[algorithm], jwtid="token-2", now=() -> 1000.0)
    @test_throws JWTs.JWTClaimError verify(wrong_jti, signed(base_payload))

    wrong_nonce = Verifier(keyset; algorithms=[algorithm], nonce="nonce-2", now=() -> 1000.0)
    @test_throws JWTs.JWTClaimError verify(wrong_nonce, signed(base_payload))

    expired = copy(base_payload)
    expired["exp"] = 999
    @test_throws JWTs.JWTClaimError verify(verifier, signed(expired))
    expires_now = copy(base_payload)
    expires_now["exp"] = 1000
    @test_throws JWTs.JWTClaimError verify(verifier, signed(expires_now))
    leeway_boundary = copy(base_payload)
    leeway_boundary["exp"] = 990
    @test_throws JWTs.JWTClaimError verify(
        Verifier(keyset; algorithms=[algorithm], leeway=10, now=() -> 1000.0),
        signed(leeway_boundary),
    )

    not_before = copy(base_payload)
    not_before["nbf"] = 1001
    @test_throws JWTs.JWTClaimError verify(verifier, signed(not_before))

    future_iat = copy(base_payload)
    future_iat["iat"] = 1001
    @test_throws JWTs.JWTClaimError verify(verifier, signed(future_iat))

    missing_required = copy(base_payload)
    delete!(missing_required, "exp")
    @test_throws JWTs.JWTClaimError verify(verifier, signed(missing_required))

    leeway_payload = copy(base_payload)
    leeway_payload["exp"] = 995
    leeway_payload["nbf"] = 1005
    leeway_payload["iat"] = 1005
    leeway_verifier = Verifier(keyset; algorithms=[algorithm], leeway=10, required_claims=["exp", "nbf", "iat"], now=() -> 1000.0)
    @test verify(leeway_verifier, signed(leeway_payload)).claims == leeway_payload

    max_age_verifier = Verifier(keyset; algorithms=[algorithm], max_age=100, now=() -> 1000.0)
    old_token = copy(base_payload)
    old_token["iat"] = 899
    @test_throws JWTs.JWTClaimError verify(max_age_verifier, signed(old_token))
    fresh_token = copy(base_payload)
    fresh_token["iat"] = 901
    @test verify(max_age_verifier, signed(fresh_token)).claims == fresh_token
end

function test_remote_jwks_and_oidc()
    print_header("remote JWKS and OIDC discovery")

    issuer = "https://issuer.example/oauth2/default"
    jwks_uri = "https://issuer.example/oauth2/default/keys"
    rsa_dir = joinpath(@__DIR__, "keys", "rsa")
    jwks_path = joinpath(rsa_dir, "jwkkey.json")
    doc1 = jwks_doc_with_kids(jwks_path, ["rsakey1"])
    doc_key2 = jwks_doc_with_kids(jwks_path, ["rsakey2"])
    doc2 = jwks_doc_with_kids(jwks_path, ["rsakey1", "rsakey2"])
    signingkeyset = signing_keyset_from_jwks_doc(doc2, rsa_dir)
    clock = TestClock(1000.0)
    payload = Dict{String,Any}(
        "iss" => issuer,
        "sub" => "remote-user",
        "aud" => "api://default",
        "exp" => 2000,
        "iat" => 900,
    )

    current_jwks = Ref{Any}(doc1)
    fetch_counts = Dict{String,Int}()
    fetcher = function(url)
        fetch_counts[url] = get(fetch_counts, url, 0) + 1
        url == jwks_uri || throw(ErrorException("unexpected URL $url"))
        return current_jwks[]
    end

    verifier = Verifier(;
        jwks_uri=jwks_uri,
        algorithms=["RS256"],
        issuer=issuer,
        audience="api://default",
        jwks_ttl=60,
        refresh_cooldown=10,
        fetcher=fetcher,
        now=clock,
        cache_now=clock,
    )

    jwt1 = signed_with_key(signingkeyset, "rsakey1", "rsakey1", payload)
    @test verify(verifier, jwt1).claims == payload
    @test fetch_counts[jwks_uri] == 1
    @test verify(verifier, string(jwt1)).claims == payload
    @test fetch_counts[jwks_uri] == 1

    clock.value += 61
    @test verify(verifier, jwt1).claims == payload
    @test fetch_counts[jwks_uri] == 2

    current_jwks[] = doc2
    jwt2 = signed_with_key(signingkeyset, "rsakey2", "rsakey2", payload)
    @test JWTs.kid(verify(verifier, jwt2)) == "rsakey2"
    @test fetch_counts[jwks_uri] == 3

    clock.value += 11
    missing_kid = signed_with_key(signingkeyset, "rsakey1", "missing-rsa-key", payload)
    @test_throws JWTs.JWKSError verify(verifier, missing_kid)
    @test fetch_counts[jwks_uri] == 4
    @test_throws JWTs.JWKSError verify(verifier, missing_kid)
    @test fetch_counts[jwks_uri] == 4

    # A TTL refresh that still cannot resolve an unknown kid must not fetch twice
    # during the same verification request.
    duplicate_clock = TestClock(1000.0)
    duplicate_fetches = Ref(0)
    duplicate_verifier = Verifier(;
        jwks_uri="https://issuer.example/duplicate-keys",
        algorithms=["RS256"],
        jwks_ttl=60,
        refresh_cooldown=10,
        fetcher=_ -> (duplicate_fetches[] += 1; doc1),
        now=duplicate_clock,
        cache_now=duplicate_clock,
    )
    @test verify(duplicate_verifier, jwt1).claims == payload
    @test duplicate_fetches[] == 1
    duplicate_clock.value += 61
    @test_throws JWTs.JWKSError verify(duplicate_verifier, missing_kid)
    @test duplicate_fetches[] == 2

    # A TTL refresh also consumes the retry budget when the cached kid exists but
    # the new token has an invalid signature. One verify must not fetch twice.
    signature_clock = TestClock(1000.0)
    signature_fetches = Ref(0)
    signature_verifier = Verifier(;
        jwks_uri="https://issuer.example/signature-keys",
        algorithms=["RS256"],
        jwks_ttl=60,
        refresh_cooldown=10,
        fetcher=_ -> (signature_fetches[] += 1; doc1),
        now=signature_clock,
        cache_now=signature_clock,
    )
    wrong_known_key = signed_with_key(
        signingkeyset,
        "rsakey2",
        "rsakey1",
        payload,
    )
    @test verify(signature_verifier, jwt1).claims == payload
    signature_clock.value += 61
    @test_throws JWTs.JWTVerificationError verify(
        signature_verifier,
        wrong_known_key,
    )
    @test signature_fetches[] == 2

    # A no-kid issuer can rotate its sole key. One cooldown-bounded refresh and one
    # signature retry should accept the new token.
    rotation_clock = TestClock(1000.0)
    rotation_doc = Ref{Any}(doc1)
    rotation_fetches = Ref(0)
    rotation_verifier = Verifier(;
        jwks_uri="https://issuer.example/rotating-keys",
        algorithms=["RS256"],
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=_ -> (rotation_fetches[] += 1; rotation_doc[]),
        now=rotation_clock,
        cache_now=rotation_clock,
    )
    no_kid_1 = signed_with_key(signingkeyset, "rsakey1", "", payload)
    no_kid_2 = signed_with_key(signingkeyset, "rsakey2", "", payload)
    @test verify(rotation_verifier, no_kid_1).claims == payload
    @test rotation_fetches[] == 1
    # The initial cache fill is not a kid-triggered refresh. A later rotation may
    # use the first miss budget even when it happens before one cooldown elapses.
    rotation_clock.value += 5
    rotation_doc[] = doc_key2
    @test verify(rotation_verifier, no_kid_2).claims == payload
    @test rotation_fetches[] == 2
    @test_throws JWTs.JWTVerificationError verify(rotation_verifier, no_kid_1)
    @test rotation_fetches[] == 2

    # A miss refresh must not hold the state lock needed by cached known-key checks.
    remote_fetch_started = Channel{Nothing}(1)
    release_remote_fetch = Channel{Nothing}(1)
    block_remote = Ref(false)
    blocking_remote = Verifier(;
        jwks_uri="https://issuer.example/blocking-keys",
        algorithms=["RS256"],
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=function (_)
            if block_remote[]
                put!(remote_fetch_started, nothing)
                take!(release_remote_fetch)
            end
            return doc1
        end,
        now=rotation_clock,
        cache_now=rotation_clock,
    )
    @test verify(blocking_remote, jwt1).claims == payload
    block_remote[] = true
    rotation_clock.value += 11
    remote_miss_task = @async try
        verify(blocking_remote, missing_kid)
    catch e
        e
    end
    take!(remote_fetch_started)
    remote_known_task = @async verify(blocking_remote, jwt1)
    remote_known_result = timedwait(() -> istaskdone(remote_known_task), 1.0)
    put!(release_remote_fetch, nothing)
    @test remote_known_result == :ok
    @test fetch(remote_known_task).claims == payload
    @test fetch(remote_miss_task) isa JWTs.JWKSError

    malformed_verifier = Verifier(;
        jwks_uri="https://issuer.example/bad-keys",
        algorithms=["RS256"],
        fetcher=url -> "{bad json",
        now=clock,
        cache_now=clock,
    )
    @test_throws JWTs.JWKSError verify(malformed_verifier, jwt1)

    failing_verifier = Verifier(;
        jwks_uri="https://issuer.example/failing-keys",
        algorithms=["RS256"],
        fetcher=url -> throw(ErrorException("network down")),
        now=clock,
        cache_now=clock,
    )
    @test_throws JWTs.JWKSError verify(failing_verifier, jwt1)

    explicit_failures = Ref(0)
    explicit_source = JWTs.RemoteJWKSet(
        "https://issuer.example/explicit-failing-keys";
        fetcher=_ -> (explicit_failures[] += 1; error("network down")),
        now=clock,
    )
    @test_throws JWTs.JWKSError refresh!(explicit_source)
    @test_throws JWTs.JWKSError refresh!(explicit_source)
    @test explicit_failures[] == 2

    discovery_url = JWTs.openid_configuration_url(issuer * "/", ".well-known/openid-configuration")
    @test discovery_url == issuer * "/.well-known/openid-configuration"

    discovery_counts = Dict{String,Int}()
    discovery_fetcher = function(url)
        discovery_counts[url] = get(discovery_counts, url, 0) + 1
        if url == discovery_url
            return Dict("issuer" => issuer, "jwks_uri" => jwks_uri)
        elseif url == jwks_uri
            return doc2
        else
            throw(ErrorException("unexpected URL $url"))
        end
    end

    oidc_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        metadata_ttl=30,
        jwks_ttl=60,
        refresh_cooldown=10,
        fetcher=discovery_fetcher,
        now=clock,
        cache_now=clock,
    )
    @test verify(oidc_verifier, jwt2).claims == payload
    @test discovery_counts[discovery_url] == 1
    @test discovery_counts[jwks_uri] == 1
    @test verify(oidc_verifier, jwt2).claims == payload
    @test discovery_counts[discovery_url] == 1
    @test discovery_counts[jwks_uri] == 1

    # Expired metadata and keys are one composite refresh. An unresolved kid must
    # not start a second discovery request during the same verify call.
    clock.value += 61
    @test_throws JWTs.JWKSError verify(oidc_verifier, missing_kid)
    @test discovery_counts[discovery_url] == 2
    @test discovery_counts[jwks_uri] == 2

    # Stage discovery and keys together. A bad replacement URI must not discard
    # the last complete key set.
    uri_a = "https://issuer.example/keys-a"
    uri_b = "https://issuer.example/keys-b"
    uri_clock = TestClock(1000.0)
    current_uri = Ref(uri_a)
    fail_uri_b = Ref(false)
    uri_counts = Dict{String,Int}()
    uri_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        metadata_ttl=300,
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=function (url)
            uri_counts[url] = get(uri_counts, url, 0) + 1
            url == discovery_url &&
                return Dict("issuer" => issuer, "jwks_uri" => current_uri[])
            url == uri_a && return doc1
            if url == uri_b
                fail_uri_b[] && error("replacement JWKS unavailable")
                return doc_key2
            end
            error("unexpected URL $url")
        end,
        now=uri_clock,
        cache_now=uri_clock,
    )
    @test verify(uri_verifier, jwt1).claims == payload
    current_uri[] = uri_b
    fail_uri_b[] = true
    uri_clock.value += 11
    @test_throws JWTs.JWKSError verify(uri_verifier, jwt2)
    @test uri_verifier.keyset.jwks.jwks_uri == uri_a
    @test verify(uri_verifier, jwt1).claims == payload
    fail_uri_b[] = false
    uri_clock.value += 11
    @test verify(uri_verifier, jwt2).claims == payload
    @test uri_verifier.keyset.jwks.jwks_uri == uri_b
    @test uri_counts[discovery_url] == 3
    @test uri_counts[uri_a] == 1
    @test uri_counts[uri_b] == 2

    # A JWKS TTL refresh must discover a changed URI before fetching keys. The
    # token keeps the same kid, so only the signature reveals the rotation.
    shared_kid = "shared-rsa"
    shared_doc1 = deepcopy(doc1)
    shared_doc2 = deepcopy(doc_key2)
    shared_doc1["keys"][1]["kid"] = shared_kid
    shared_doc2["keys"][1]["kid"] = shared_kid
    shared_token1 = signed_with_key(
        signingkeyset,
        "rsakey1",
        shared_kid,
        payload,
    )
    shared_token2 = signed_with_key(
        signingkeyset,
        "rsakey2",
        shared_kid,
        payload,
    )
    shared_clock = TestClock(1000.0)
    shared_uri = Ref(uri_a)
    shared_counts = Dict{String,Int}()
    shared_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        metadata_ttl=600,
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=function (url)
            shared_counts[url] = get(shared_counts, url, 0) + 1
            url == discovery_url &&
                return Dict("issuer" => issuer, "jwks_uri" => shared_uri[])
            url == uri_a && return shared_doc1
            url == uri_b && return shared_doc2
            error("unexpected URL $url")
        end,
        now=shared_clock,
        cache_now=shared_clock,
    )
    @test verify(shared_verifier, shared_token1).claims == payload
    shared_uri[] = uri_b
    shared_clock.value += 301
    @test verify(shared_verifier, shared_token2).claims == payload
    @test shared_counts[discovery_url] == 2
    @test shared_counts[uri_a] == 1
    @test shared_counts[uri_b] == 1

    # All waiters observe the new source identity and generation after one caller
    # completes a same-kid rotation refresh.
    concurrent_clock = TestClock(1000.0)
    concurrent_doc = Ref{Any}(doc1)
    block_discovery = Ref(false)
    discovery_started = Channel{Nothing}(1)
    release_discovery = Channel{Nothing}(1)
    concurrent_discovery_fetches = Ref(0)
    concurrent_jwks_fetches = Ref(0)
    concurrent_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        metadata_ttl=300,
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=function (url)
            if url == discovery_url
                concurrent_discovery_fetches[] += 1
                if block_discovery[]
                    put!(discovery_started, nothing)
                    take!(release_discovery)
                end
                return Dict("issuer" => issuer, "jwks_uri" => jwks_uri)
            end
            url == jwks_uri || error("unexpected URL $url")
            concurrent_jwks_fetches[] += 1
            return concurrent_doc[]
        end,
        now=concurrent_clock,
        cache_now=concurrent_clock,
    )
    concurrent_token = signed_with_key(
        signingkeyset,
        "rsakey2",
        "rsakey1",
        payload,
    )
    @test verify(concurrent_verifier, jwt1).claims == payload
    concurrent_doc[] = deepcopy(doc_key2)
    concurrent_doc[]["keys"][1]["kid"] = "rsakey1"
    concurrent_clock.value += 11
    block_discovery[] = true
    first_waiter = @async verify(concurrent_verifier, concurrent_token)
    take!(discovery_started)
    second_waiter = @async verify(concurrent_verifier, concurrent_token)
    yield()
    @test !istaskdone(second_waiter)
    put!(release_discovery, nothing)
    @test fetch(first_waiter).claims == payload
    @test fetch(second_waiter).claims == payload
    @test concurrent_discovery_fetches[] == 2
    @test concurrent_jwks_fetches[] == 2

    # A same-URI OIDC refresh stages the new nested source. A waiter that samples
    # after the staged JWKS fetch but before the outer commit must not start a
    # second discovery/JWKS request.
    atomic_clock_value = Ref(1000.0)
    atomic_arm = Ref(false)
    atomic_after_jwks = Ref(false)
    atomic_post_fetch_clock_calls = Ref(0)
    atomic_commit_started = Channel{Nothing}(1)
    release_atomic_commit = Channel{Nothing}(1)
    atomic_clock = function ()
        if atomic_after_jwks[]
            atomic_post_fetch_clock_calls[] += 1
            if atomic_post_fetch_clock_calls[] == 2
                put!(atomic_commit_started, nothing)
                take!(release_atomic_commit)
                atomic_after_jwks[] = false
                atomic_arm[] = false
            end
        end
        return atomic_clock_value[]
    end
    atomic_discovery_fetches = Ref(0)
    atomic_jwks_fetches = Ref(0)
    atomic_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        metadata_ttl=300,
        jwks_ttl=300,
        refresh_cooldown=10,
        fetcher=function (url)
            if url == discovery_url
                atomic_discovery_fetches[] += 1
                return Dict("issuer" => issuer, "jwks_uri" => jwks_uri)
            end
            url == jwks_uri || error("unexpected URL $url")
            atomic_jwks_fetches[] += 1
            if atomic_arm[]
                atomic_post_fetch_clock_calls[] = 0
                atomic_after_jwks[] = true
            end
            return doc1
        end,
        now=atomic_clock,
        cache_now=atomic_clock,
    )
    @test verify(atomic_verifier, jwt1).claims == payload
    atomic_clock_value[] += 301
    atomic_arm[] = true
    atomic_refresh_task = @async verify(atomic_verifier, jwt1)
    take!(atomic_commit_started)
    atomic_miss_task = @async try
        verify(atomic_verifier, missing_kid)
    catch e
        e
    end
    yield()
    @test !istaskdone(atomic_miss_task)
    put!(release_atomic_commit, nothing)
    @test fetch(atomic_refresh_task).claims == payload
    @test fetch(atomic_miss_task) isa JWTs.JWKSError
    @test atomic_discovery_fetches[] == 2
    @test atomic_jwks_fetches[] == 2

    missing_jwks_fetcher = url -> Dict("issuer" => issuer)
    missing_jwks_verifier = Verifier(
        issuer;
        algorithms=["RS256"],
        audience="api://default",
        fetcher=missing_jwks_fetcher,
        now=clock,
        cache_now=clock,
    )
    @test_throws JWTs.JWKSError verify(missing_jwks_verifier, jwt1)
end

@testset "JWTs" begin
    @testset "signing" begin
        test_and_get_keyset("file://" * joinpath(@__DIR__, "keys", "rsa", "jwkkey.json"))
        test_signing_symmetric_keys("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"), ["HS256", "HS384", "HS512"])
        test_in_mem_keyset(joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
        test_signing_asymmetric_keys("file://" * joinpath(@__DIR__, "keys", "rsa", "jwkkey.json"), ["RS256"])
        test_signing_asymmetric_keys("file://" * joinpath(@__DIR__, "keys", "rsa_ps", "jwkkey.json"), ["PS256", "PS384", "PS512"])
        test_signing_asymmetric_keys("file://" * joinpath(@__DIR__, "keys", "ec", "jwkkey.json"), ["ES256", "ES384", "ES512"])
        test_signing_asymmetric_keys("file://" * joinpath(@__DIR__, "keys", "okp", "jwkkey.json"), ["EdDSA"])
        test_with_valid_jwt("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"), ["HS256", "HS384", "HS512"])
        test_validation_state_safety("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
        test_verifier_claims("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
        test_remote_jwks_and_oidc()
    end

    @testset "alg" begin
        rsakey = JWTs.parse_keyfile(joinpath(@__DIR__, "keys", "rsa", "rsakey1.private.pem"))
        @test JWTs.alg(JWKRSA("RS256", rsakey)) == "RS256"
        @test JWTs.alg(JWKRSA("RS384", rsakey)) == "RS384"
        @test JWTs.alg(JWKRSA("RS512", rsakey)) == "RS512"

        @test JWTs.alg(JWKSymmetric("HS256", UInt8[])) == "HS256"
        @test JWTs.alg(JWKSymmetric("HS384", UInt8[])) == "HS384"
        @test JWTs.alg(JWKSymmetric("HS512", UInt8[])) == "HS512"

        @test_throws ArgumentError JWKRSA("RS1024", rsakey)
        @test_throws ArgumentError JWKSymmetric("HS1024", UInt8[])

        eckey = JWTs.parse_keyfile(joinpath(@__DIR__, "keys", "ec", "es256-1.private.pem"))
        @test JWTs.alg(JWTs.JWKEC("ES256", eckey, "P-256")) == "ES256"
        @test_throws ArgumentError JWTs.JWKEC("ES384", eckey, "P-256")

        okpkey = JWTs.parse_keyfile(joinpath(@__DIR__, "keys", "okp", "eddsa-1.private.pem"))
        @test JWTs.alg(JWTs.JWKOKP("EdDSA", okpkey, "Ed25519")) == "EdDSA"
        @test_throws ArgumentError JWTs.JWKOKP("EdDSA", okpkey, "Ed448")
    end

    @testset "malformed jwks" begin
        keysetdict = Dict{String,JWK}()
        bad_ec = [Dict(
            "kid" => "bad-ec",
            "kty" => "EC",
            "alg" => "ES256",
            "use" => "sig",
            "crv" => "P-256",
            "x" => JWTs.base64url_encode(UInt8[0x01]),
            "y" => JWTs.base64url_encode(UInt8[0x02]),
        )]
        JWTs.refresh!(bad_ec, keysetdict)
        @test isempty(keysetdict)

        bad_okp = [Dict(
            "kid" => "bad-okp",
            "kty" => "OKP",
            "alg" => "EdDSA",
            "use" => "sig",
            "crv" => "Ed25519",
            "x" => JWTs.base64url_encode(UInt8[0x01]),
        )]
        JWTs.refresh!(bad_okp, keysetdict)
        @test isempty(keysetdict)
    end

    @testset "hardening" begin
        # strict base64url decoding: canonical round-trips, everything else is rejected
        @test JWTs.base64url_decode(JWTs.base64url_encode(UInt8[0x00, 0x01, 0xfe, 0xff])) == UInt8[0x00, 0x01, 0xfe, 0xff]
        @test JWTs.base64url_decode("YQ==") == UInt8[0x61] # canonical padded base64url is accepted
        @test_throws ArgumentError JWTs.base64url_decode("ab+c")   # standard-base64 '+'
        @test_throws ArgumentError JWTs.base64url_decode("ab/c")   # standard-base64 '/'
        @test_throws ArgumentError JWTs.base64url_decode("YQ=x")   # '=' before the end
        @test_throws ArgumentError JWTs.base64url_decode("AA=")    # wrong padding count
        @test_throws ArgumentError JWTs.base64url_decode("AA===")  # excess trailing padding
        @test_throws ArgumentError JWTs.base64url_decode("AAA==")  # excess trailing padding
        @test_throws ArgumentError JWTs.base64url_decode("YQ===")  # excess trailing padding
        @test_throws ArgumentError JWTs.base64url_decode("YQABC")  # length % 4 == 1
        @test_throws ArgumentError JWTs.base64url_decode("QB")     # non-zero trailing bits

        @test JWTs.is_http_url("https://issuer.example/keys")
        @test JWTs.is_http_url("http://issuer.example/keys")
        @test !JWTs.is_http_url("file:///etc/passwd")

        # a remote JWKS must not yield a symmetric (forge-able) key
        secret = collect(codeunits("remote-symmetric-secret"))
        sym_doc = Dict("keys" => [Dict("kid" => "sym1", "kty" => "oct", "alg" => "HS256", "k" => JWTs.base64url_encode(secret))])
        sym_verifier = Verifier(; jwks_uri="https://issuer.example/keys", algorithms=["HS256"], fetcher=(_ -> sym_doc), now=() -> 1000.0)
        sym_jwt = JWT(; payload=Dict("sub" => "x"))
        sign!(sym_jwt, JWKSymmetric("HS256", secret), "sym1")
        @test_throws JWTs.JWKSError verify(sym_verifier, sym_jwt)

        direct_remote_keyset = JWKSet("https://issuer.example/keys")
        refresh!(direct_remote_keyset; fetcher=(_ -> JSON.json(sym_doc)))
        @test isempty(direct_remote_keyset.keys)

        direct_trusted_keyset = JWKSet("https://issuer.example/keys")
        refresh!(direct_trusted_keyset; fetcher=(_ -> JSON.json(sym_doc)), allow_symmetric=true)
        @test haskey(direct_trusted_keyset.keys, "sym1")

        # OIDC discovery binds an exact HTTPS issuer to an HTTPS JWKS endpoint.
        oidc_issuer = "https://issuer.example/oauth2/default"
        resolvable = JWTs.base64url_encode(JSON.json(Dict("alg" => "RS256", "kid" => "k1", "typ" => "JWT"))) * "." *
            JWTs.base64url_encode(JSON.json(Dict("sub" => "x"))) * "." * JWTs.base64url_encode(UInt8[0x00])
        @test_throws ArgumentError Verifier(
            "http://issuer.example";
            algorithms=["RS256"],
        )
        no_issuer = Verifier(oidc_issuer; algorithms=["RS256"], fetcher=(_ -> Dict("jwks_uri" => "https://issuer.example/keys")), now=() -> 1000.0)
        @test_throws JWTs.JWKSError verify(no_issuer, resolvable)
        file_jwks = Verifier(oidc_issuer; algorithms=["RS256"], fetcher=(_ -> Dict("issuer" => oidc_issuer, "jwks_uri" => "file:///etc/passwd")), now=() -> 1000.0)
        @test_throws JWTs.JWKSError verify(file_jwks, resolvable)
        http_jwks = Verifier(oidc_issuer; algorithms=["RS256"], fetcher=(_ -> Dict("issuer" => oidc_issuer, "jwks_uri" => "http://issuer.example/keys")), now=() -> 1000.0)
        @test_throws JWTs.JWKSError verify(http_jwks, resolvable)

        # the verifier surfaces typed errors for malformed tokens and missing expected claims
        oct_keyset = JWKSet("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
        refresh!(oct_keyset)
        oct_kid = first(k for (k, v) in oct_keyset.keys if JWTs.alg(v) == "HS256")
        signed_token = JWT(; payload=Dict("sub" => "s"))
        sign!(signed_token, oct_keyset, oct_kid)
        plain_verifier = Verifier(oct_keyset; algorithms=["HS256"], now=() -> 1000.0)
        @test_throws JWTs.JWTVerificationError verify(plain_verifier, "a*b.c.d")
        issuer_verifier = Verifier(oct_keyset; algorithms=["HS256"], issuer="https://issuer.example", now=() -> 1000.0)
        missing_iss_err = try
            verify(issuer_verifier, signed_token)
            nothing
        catch e
            e
        end
        @test missing_iss_err isa JWTs.JWTClaimError
        @test missing_iss_err.code === :claim_missing
    end
end

@testset "hardening: expiry, kid, and refresh bounds" begin
    keydir = joinpath(@__DIR__, "keys", "rsa")
    priv = JWTs.JWKRSA("RS256", JWTs.parse_keyfile(joinpath(keydir, "rsakey1.private.pem")))
    pub = JWTs.JWKRSA("RS256", JWTs.parse_keyfile(joinpath(keydir, "rsakey1.public.pem")))
    pubset = JWKSet("")
    pubset.keys["k1"] = pub
    now_s = round(Int, time())

    signed(payload; header_kid = "k1") = begin
        jwt = JWT(; payload = payload)
        sign!(jwt, priv, header_kid)
        jwt
    end

    @testset "with_valid_jwt expiry" begin
        expired = signed(Dict("sub" => "u", "exp" => now_s - 3600))
        # a signature-valid but expired token must not reach the callback
        ran = Ref(false)
        err = try
            with_valid_jwt(expired, pubset) do _
                ran[] = true
            end
            nothing
        catch e
            e
        end
        @test !ran[]
        @test err isa JWTs.JWTClaimError
        @test err.code === :token_expired

        # opting out restores the old signature-only behaviour
        ran[] = false
        with_valid_jwt(expired, pubset; check_expiry = false) do _
            ran[] = true
        end
        @test ran[]

        # leeway can absorb clock skew
        just_expired = signed(Dict("sub" => "u", "exp" => now_s - 10))
        @test_throws JWTs.JWTClaimError with_valid_jwt(identity, just_expired, pubset)
        @test with_valid_jwt(_ -> :ok, just_expired, pubset; leeway = 60) === :ok
        @test_throws ArgumentError with_valid_jwt(identity, just_expired, pubset; leeway = -1)
        for invalid_seconds in (NaN, Inf, -Inf)
            @test_throws ArgumentError with_valid_jwt(
                identity,
                just_expired,
                pubset;
                leeway=invalid_seconds,
            )
            @test_throws ArgumentError Verifier(
                pubset;
                algorithms=["RS256"],
                leeway=invalid_seconds,
            )
            @test_throws ArgumentError Verifier(
                pubset;
                algorithms=["RS256"],
                max_age=invalid_seconds,
            )
        end
        @test_throws ArgumentError with_valid_jwt(
            identity,
            just_expired,
            pubset;
            now=Inf,
        )
        # RFC 7519 requires the current time to be strictly before exp.
        @test_throws JWTs.JWTClaimError with_valid_jwt(
            identity,
            signed(Dict("sub" => "u", "exp" => now_s)),
            pubset;
            now=now_s,
        )
        @test_throws JWTs.JWTClaimError with_valid_jwt(
            identity,
            signed(Dict("sub" => "u", "exp" => now_s - 10)),
            pubset;
            now=now_s,
            leeway=10,
        )
        huge_expiry = JWT(;
            payload=JWTs.base64url_encode("""{"sub":"u","exp":1e1000}"""),
        )
        sign!(huge_expiry, priv, "k1")
        @test_throws JWTs.JWTClaimError with_valid_jwt(
            identity,
            huge_expiry,
            pubset,
        )
        @test_throws JWTs.JWTClaimError verify(
            Verifier(pubset; algorithms=["RS256"]),
            huge_expiry,
        )

        # nbf is enforced too
        future = signed(Dict("sub" => "u", "nbf" => now_s + 3600))
        nbf_err = try
            with_valid_jwt(identity, future, pubset)
        catch e
            e
        end
        @test nbf_err isa JWTs.JWTClaimError
        @test nbf_err.code === :token_not_yet_valid

        # a live token still passes, and tokens without time claims are unaffected
        @test with_valid_jwt(_ -> :ok, signed(Dict("sub" => "u", "exp" => now_s + 3600)), pubset) === :ok
        @test with_valid_jwt(_ -> :ok, signed(Dict("sub" => "u")), pubset) === :ok

        malformed_payload = JWT(; payload = Any["not", "an", "object"])
        sign!(malformed_payload, priv, "k1")
        malformed_err = try
            with_valid_jwt(identity, malformed_payload, pubset)
        catch e
            e
        end
        @test malformed_err isa JWTs.JWTClaimError
        @test malformed_err.code === :malformed_payload

        # The live clock is sampled after signature/key work, not at function entry.
        clock_sample = JWT(; jwt=string(signed(Dict("sub" => "u", "exp" => 1500))))
        @test !isverified(clock_sample)
        @test_throws JWTs.JWTClaimError with_valid_jwt(
            identity,
            clock_sample,
            pubset;
            now=() -> isverified(clock_sample) ? 2000.0 : 1000.0,
        )

        # validate! remains signature-only by documented design
        @test validate!(signed(Dict("sub" => "u", "exp" => now_s - 3600)), pubset)
    end

    @testset "critical JOSE headers" begin
        verifier = JWTs.Verifier(pubset; algorithms=["RS256"])
        base_header = Dict{String,Any}("alg" => "RS256", "kid" => "k1", "typ" => "JWT")

        # RFC 7797 forbids unencoded payloads in JWTs. Without this check, signed JWS
        # data can be decoded as JWT claims in a cross-protocol substitution.
        unencoded_header = merge(base_header, Dict("b64" => false, "crit" => ["b64"]))
        unencoded = signed_with_header(priv, Dict("admin" => true), unencoded_header)
        @test validate!(JWT(; jwt=string(unencoded)), pubset)
        @test_throws JWTs.JWTVerificationError JWTs.verify(verifier, unencoded)
        @test_throws JWTs.JWTVerificationError with_valid_jwt(identity, unencoded, pubset)
        @test_throws JWTs.JWTVerificationError with_valid_jwt(
            identity,
            unencoded,
            pubset;
            check_expiry=false,
        )

        accepted_b64 = signed_with_header(
            priv,
            Dict("sub" => "u"),
            merge(base_header, Dict("b64" => true, "crit" => ["b64"])),
        )
        @test JWTs.claims(JWTs.verify(verifier, accepted_b64))["sub"] == "u"

        invalid_headers = [
            merge(base_header, Dict("crit" => Any[])),
            merge(base_header, Dict("crit" => "b64", "b64" => true)),
            merge(base_header, Dict("crit" => ["b64"])),
            merge(base_header, Dict("crit" => ["b64", "b64"], "b64" => true)),
            merge(base_header, Dict("crit" => ["unknown"], "unknown" => true)),
            merge(base_header, Dict("b64" => "true")),
            merge(base_header, Dict("b64" => true)),
        ]
        for header in invalid_headers
            token = signed_with_header(priv, Dict("sub" => "u"), header)
            @test_throws JWTs.JWTVerificationError JWTs.verify(verifier, token)
            @test_throws JWTs.JWTVerificationError with_valid_jwt(identity, token, pubset)
            @test_throws JWTs.JWTVerificationError with_valid_jwt(
                identity,
                token,
                pubset;
                check_expiry=false,
            )
        end
    end

    @testset "JWK operation intent" begin
        source_key = deepcopy(JSON.parse(
            read(joinpath(keydir, "jwkkey.json"), String))["keys"][1])
        operation_token = JWT(; payload=Dict("sub" => "operation-intent"))
        sign!(operation_token, priv, source_key["kid"])

        disallowed_keys = Any[
            merge(source_key, Dict("use" => "enc")),
            merge(source_key, Dict("use" => "sig", "key_ops" => ["sign"])),
            merge(source_key, Dict("use" => "sig", "key_ops" => "verify")),
        ]
        for disallowed_key in disallowed_keys
            delete!(disallowed_key, "alg")
            verifier = Verifier(;
                jwks_uri="https://issuer.example/operation-keys",
                algorithms=["RS256"],
                fetcher=_ -> Dict("keys" => [disallowed_key]),
            )
            @test_throws JWTs.JWKSError verify(verifier, operation_token)
        end

        allowed_key = merge(
            source_key,
            Dict("use" => "sig", "key_ops" => ["verify"]),
        )
        delete!(allowed_key, "alg")
        verifier = Verifier(;
            jwks_uri="https://issuer.example/operation-keys",
            algorithms=["RS256"],
            fetcher=_ -> Dict("keys" => [allowed_key]),
        )
        @test claims(verify(verifier, operation_token))["sub"] == "operation-intent"

        # Generic vector and URL-backed JWK sets retain operation metadata too.
        # A signing-only public key must not become a verification key when parsed.
        sign_only_key = merge(
            source_key,
            Dict("use" => "sig", "key_ops" => ["sign"]),
        )
        vector_keyset = JWKSet([sign_only_key])
        @test_throws JWTs.JWTVerificationError verify(
            Verifier([sign_only_key]; algorithms=["RS256"]),
            operation_token,
        )
        @test_throws JWTs.JWTVerificationError verify(
            Verifier(vector_keyset; algorithms=["RS256"]),
            operation_token,
        )
        @test_throws ArgumentError with_valid_jwt(
            identity,
            operation_token,
            vector_keyset,
        )

        direct_keyset = JWKSet(
            "custom://operation-keys";
            fetcher=_ -> Dict("keys" => [sign_only_key]),
        )
        refresh!(direct_keyset)
        @test_throws JWTs.JWTVerificationError verify(
            Verifier(direct_keyset; algorithms=["RS256"]),
            operation_token,
        )

        # Operation intent is enforced in the opposite direction as well.
        secret = collect(codeunits("operation-intent-secret"))
        verify_only_symmetric = Dict(
            "kty" => "oct",
            "kid" => "verify-only",
            "alg" => "HS256",
            "k" => JWTs.base64url_encode(secret),
            "use" => "sig",
            "key_ops" => ["verify"],
        )
        verify_only_keyset = JWKSet([verify_only_symmetric])
        @test_throws ArgumentError sign!(
            JWT(; payload=Dict("sub" => "operation-intent")),
            verify_only_keyset,
            "verify-only",
        )

        sign_only_symmetric = merge(
            verify_only_symmetric,
            Dict("kid" => "sign-only", "key_ops" => ["sign"]),
        )
        sign_only_keyset = JWKSet([sign_only_symmetric])
        sign_only_token = JWT(; payload=Dict("sub" => "operation-intent"))
        sign!(sign_only_token, sign_only_keyset, "sign-only")
        @test_throws JWTs.JWTVerificationError verify(
            Verifier(sign_only_keyset; algorithms=["HS256"]),
            sign_only_token,
        )
    end

    @testset "kid is optional when the key set is unambiguous" begin
        no_kid = JWT(; payload = Dict("sub" => "u"))
        sign!(no_kid, priv)
        @test JWTs.kid(no_kid) === nothing
        verifier = JWTs.Verifier(pubset; algorithms = ["RS256"])
        verified = JWTs.verify(verifier, no_kid)
        @test JWTs.claims(verified)["sub"] == "u"
        # the resolved key id is reported even though the header omitted it
        @test JWTs.kid(verified) == "k1"

        # ambiguous key sets still demand a kid
        two = JWKSet("")
        two.keys["k1"] = pub
        two.keys["k2"] = JWTs.JWKRSA("RS256", JWTs.parse_keyfile(joinpath(keydir, "rsakey2.public.pem")))
        ambiguous = JWTs.Verifier(two; algorithms = ["RS256"])
        err = try
            JWTs.verify(ambiguous, no_kid)
        catch e
            e
        end
        @test err isa JWTs.JWTVerificationError
        @test err.code === :key_id_missing

        # a kid that is present is still honoured, and an unknown one still fails
        @test JWTs.kid(JWTs.verify(ambiguous, signed(Dict("sub" => "u")))) == "k1"
        unknown = signed(Dict("sub" => "u"); header_kid = "nope")
        @test_throws JWTs.JWKSError JWTs.verify(ambiguous, unknown)

        # Optional means absent. A present kid with the wrong JSON type is malformed.
        for malformed_kid in Any[nothing, 123, true, Any["k1"], Dict("id" => "k1")]
            malformed = signed_with_header(
                priv,
                Dict("sub" => "u"),
                Dict("alg" => "RS256", "kid" => malformed_kid, "typ" => "JWT"),
            )
            malformed_err = try
                JWTs.verify(verifier, malformed)
                nothing
            catch e
                e
            end
            @test malformed_err isa JWTs.JWTVerificationError
            @test malformed_err.code === :key_id_invalid
        end
    end

    @testset "kid optional for remote and OIDC key sources" begin
        # the same single-key rule must hold for RemoteJWKSet and OIDCDiscovery,
        # not just an in-memory JWKSet
        jwk_doc = JSON.parse(read(joinpath(keydir, "jwkkey.json"), String))
        sole = Dict("keys" => [jwk_doc["keys"][1]])
        sole2 = Dict("keys" => [jwk_doc["keys"][2]])
        sole_kid = sole["keys"][1]["kid"]
        sole_priv = JWTs.JWKRSA("RS256", JWTs.parse_keyfile(joinpath(keydir, "rsakey1.private.pem")))
        sole_priv2 = JWTs.JWKRSA("RS256", JWTs.parse_keyfile(joinpath(keydir, "rsakey2.private.pem")))

        no_kid = JWT(; payload = Dict("sub" => "remote"))
        sign!(no_kid, sole_priv)
        @test JWTs.kid(no_kid) === nothing

        remote = JWTs.Verifier(; jwks_uri = "https://issuer.example/keys",
            algorithms = ["RS256"], fetcher = (_ -> sole), now = () -> 1000.0)
        verified = JWTs.verify(remote, no_kid)
        @test JWTs.kid(verified) == sole_kid

        # Verifier(issuer_url; ...) expects a matching `iss` claim, so sign one that has it
        oidc_issuer = "https://issuer.example/oauth2/default"
        oidc_token = JWT(; payload = Dict("sub" => "remote", "iss" => oidc_issuer))
        sign!(oidc_token, sole_priv)
        oidc = JWTs.Verifier(oidc_issuer; algorithms = ["RS256"], now = () -> 1000.0,
            fetcher = function (url)
                endswith(url, "/keys") && return sole
                return Dict("issuer" => oidc_issuer, "jwks_uri" => "https://issuer.example/keys")
            end)
        @test JWTs.kid(JWTs.verify(oidc, oidc_token)) == sole_kid

        # Issuer identifiers are compared byte-for-byte. A trailing slash is retained.
        slash_issuer = "https://issuer.example/"
        slash_token = JWT(; payload=Dict("sub" => "remote", "iss" => slash_issuer))
        sign!(slash_token, sole_priv)
        slash_oidc = JWTs.Verifier(
            slash_issuer;
            algorithms=["RS256"],
            now=() -> 1000.0,
            fetcher=function (url)
                endswith(url, "/keys") && return sole
                return Dict(
                    "issuer" => slash_issuer,
                    "jwks_uri" => "https://issuer.example/keys",
                )
            end,
        )
        @test JWTs.claims(JWTs.verify(slash_oidc, slash_token))["sub"] == "remote"
        mismatched_slash = JWTs.Verifier(
            slash_issuer;
            algorithms=["RS256"],
            now=() -> 1000.0,
            fetcher=_ -> Dict(
                "issuer" => "https://issuer.example",
                "jwks_uri" => "https://issuer.example/keys",
            ),
        )
        @test_throws JWTs.JWKSError JWTs.verify(mismatched_slash, slash_token)

        # OIDC refreshes discovery and the selected JWKS as one bounded retry, so a
        # jwks_uri or sole-key rotation does not wait for metadata/JWKS TTL expiry.
        rotation_clock = TestClock(1000.0)
        rotation_doc = Ref{Any}(sole)
        discovery_fetches = Ref(0)
        jwks_fetches = Ref(0)
        rotating_oidc = JWTs.Verifier(
            oidc_issuer;
            algorithms=["RS256"],
            metadata_ttl=300,
            jwks_ttl=300,
            refresh_cooldown=10,
            now=rotation_clock,
            cache_now=rotation_clock,
            fetcher=function (url)
                if endswith(url, "/keys")
                    jwks_fetches[] += 1
                    return rotation_doc[]
                end
                discovery_fetches[] += 1
                return Dict(
                    "issuer" => oidc_issuer,
                    "jwks_uri" => "https://issuer.example/keys",
                )
            end,
        )
        rotating_token1 = JWT(; payload=Dict("sub" => "remote", "iss" => oidc_issuer))
        sign!(rotating_token1, sole_priv)
        rotating_token2 = JWT(; payload=Dict("sub" => "remote", "iss" => oidc_issuer))
        sign!(rotating_token2, sole_priv2)
        @test JWTs.verify(rotating_oidc, rotating_token1).claims["sub"] == "remote"
        @test (discovery_fetches[], jwks_fetches[]) == (1, 1)
        rotation_doc[] = sole2
        rotation_clock.value += 5
        @test JWTs.verify(rotating_oidc, rotating_token2).claims["sub"] == "remote"
        @test (discovery_fetches[], jwks_fetches[]) == (2, 2)

        # A rejected retry inside the miss cooldown does not start a nested
        # cooldown. Recovery happens when the one outer window ends.
        rotation_doc[] = sole
        rotation_clock.value += 5.1
        @test_throws JWTs.JWTVerificationError JWTs.verify(
            rotating_oidc,
            rotating_token1,
        )
        @test (discovery_fetches[], jwks_fetches[]) == (2, 2)
        rotation_clock.value += 5
        @test JWTs.verify(rotating_oidc, rotating_token1).claims["sub"] == "remote"
        @test (discovery_fetches[], jwks_fetches[]) == (3, 3)

        # more than one key remains ambiguous for a remote source too
        both = Dict("keys" => jwk_doc["keys"])
        if length(both["keys"]) > 1
            ambiguous = JWTs.Verifier(; jwks_uri = "https://issuer.example/keys",
                algorithms = ["RS256"], fetcher = (_ -> both), now = () -> 1000.0)
            err = try
                JWTs.verify(ambiguous, no_kid)
            catch e
                e
            end
            @test err isa JWTs.JWTVerificationError
            @test err.code === :key_id_missing

            # Ambiguity can disappear during rotation. All three refreshable source
            # types must retry a multi-key cache and use the newly sole key.
            no_kid_second = JWT(; payload=Dict("sub" => "remote"))
            sign!(no_kid_second, sole_priv2)

            direct_doc = Ref{Any}(both)
            direct = JWKSet(
                "custom://transition";
                fetcher=_ -> direct_doc[],
            )
            refresh!(direct)
            direct_doc[] = sole2
            @test JWTs.kid(JWTs.verify(
                JWTs.Verifier(direct; algorithms=["RS256"]),
                no_kid_second,
            )) == sole2["keys"][1]["kid"]

            transition_clock = TestClock(1000.0)
            remote_doc = Ref{Any}(both)
            remote_transition = JWTs.Verifier(;
                jwks_uri="https://issuer.example/transition-keys",
                algorithms=["RS256"],
                refresh_cooldown=10,
                fetcher=_ -> remote_doc[],
                now=transition_clock,
                cache_now=transition_clock,
            )
            explicit_first = JWT(; payload=Dict("sub" => "remote"))
            sign!(explicit_first, sole_priv, sole_kid)
            @test JWTs.verify(remote_transition, explicit_first).claims["sub"] == "remote"
            remote_doc[] = sole2
            transition_clock.value += 11
            @test JWTs.kid(JWTs.verify(
                remote_transition,
                no_kid_second,
            )) == sole2["keys"][1]["kid"]

            oidc_doc = Ref{Any}(both)
            oidc_transition = JWTs.Verifier(
                oidc_issuer;
                algorithms=["RS256"],
                refresh_cooldown=10,
                fetcher=function (url)
                    endswith(url, "/keys") && return oidc_doc[]
                    return Dict(
                        "issuer" => oidc_issuer,
                        "jwks_uri" => "https://issuer.example/keys",
                    )
                end,
                now=transition_clock,
                cache_now=transition_clock,
            )
            oidc_explicit_first = JWT(;
                payload=Dict("sub" => "remote", "iss" => oidc_issuer),
            )
            sign!(oidc_explicit_first, sole_priv, sole_kid)
            oidc_no_kid_second = JWT(;
                payload=Dict("sub" => "remote", "iss" => oidc_issuer),
            )
            sign!(oidc_no_kid_second, sole_priv2)
            @test JWTs.verify(
                oidc_transition,
                oidc_explicit_first,
            ).claims["sub"] == "remote"
            oidc_doc[] = sole2
            transition_clock.value += 11
            @test JWTs.kid(JWTs.verify(
                oidc_transition,
                oidc_no_kid_second,
            )) == sole2["keys"][1]["kid"]
        end
    end

    @testset "unknown kid does not refetch without bound" begin
        # Write a JWKS to disk and mutate it between calls: if a refetch happened the
        # keyset picks up the new key, if it was suppressed it does not. That makes the
        # cooldown observable without depending on timing or a network socket.
        jwks_path, io = mktemp()
        close(io)
        doc(kids) = JSON.json(Dict("keys" => [Dict(
            "kty" => "oct", "kid" => k, "alg" => "HS256",
            "k" => JWTs.base64url_encode("supersecretvalue")) for k in kids]))
        write(jwks_path, doc(["sym"]))
        keyset = JWKSet("file://" * jwks_path)
        JWTs.refresh!(keyset)
        @test haskey(keyset.keys, "sym")

        # publish a second key, then ask for a stream of unknown kids
        write(jwks_path, doc(["sym", "sym2"]))
        for i in 1:20
            JWTs.refresh_for_unknown_kid!(keyset, "bogus-$i")
        end
        # exactly one refetch was permitted inside the cooldown window, so the new key
        # is visible, but the other 19 requests did not each cause their own fetch
        @test haskey(keyset.keys, "sym2")

        # a third key published now must NOT be picked up while still in cooldown
        write(jwks_path, doc(["sym", "sym2", "sym3"]))
        for i in 21:40
            JWTs.refresh_for_unknown_kid!(keyset, "bogus-$i")
        end
        @test !haskey(keyset.keys, "sym3")

        # once the window elapses a refresh is allowed again
        keyset.last_key_miss_refresh_at = JWTs.cache_now_seconds(keyset) - 31.0
        JWTs.refresh_for_unknown_kid!(keyset, "bogus-after-cooldown")
        @test haskey(keyset.keys, "sym3")

        # a known kid never triggers a refresh at all
        write(jwks_path, doc(["sym", "sym2", "sym3", "sym4"]))
        keyset.last_key_miss_refresh_at = nothing
        for _ in 1:10
            JWTs.refresh_for_unknown_kid!(keyset, "sym")
        end
        @test !haskey(keyset.keys, "sym4")

        # a cooldown of zero preserves the previous unbounded-refresh behaviour
        eager = JWKSet("file://" * jwks_path; refresh_cooldown = 0)
        JWTs.refresh!(eager)
        write(jwks_path, doc(["sym", "sym5"]))
        JWTs.refresh_for_unknown_kid!(eager, "anything")
        @test haskey(eager.keys, "sym5")

        # A missing kid against an empty fetched set shares the same cooldown. It
        # cannot bypass the bound added for explicit unknown kid values.
        write(jwks_path, doc(String[]))
        empty = JWKSet("file://" * jwks_path)
        symmetric_key = JWKSymmetric(
            "HS256",
            collect(codeunits("supersecretvalue")),
        )
        no_kid = JWT(; payload=Dict("sub" => "empty"))
        sign!(no_kid, symmetric_key)
        empty_verifier = Verifier(empty; algorithms=["HS256"])
        @test_throws JWTs.JWTVerificationError verify(empty_verifier, no_kid)
        write(jwks_path, doc(["only"]))
        @test_throws JWTs.JWTVerificationError verify(empty_verifier, no_kid)
        empty.last_key_miss_refresh_at = JWTs.cache_now_seconds(empty) - 31.0
        @test kid(verify(empty_verifier, no_kid)) == "only"

        # Custom fetch settings are retained for token-driven rotation refreshes.
        custom_doc = Ref(doc(["custom-1"]))
        custom_fetches = Ref(0)
        custom = JWKSet(
            "custom://keys";
            fetcher=_ -> (custom_fetches[] += 1; custom_doc[]),
        )
        refresh!(custom)
        custom_doc[] = doc(["custom-1", "custom-2"])
        @test JWTs.refresh_for_unknown_kid!(custom, "custom-2")
        @test custom_fetches[] == 2

        # Cooldown begins when a slow failure completes, not when its fetch starts.
        failure_clock = TestClock(0.0)
        failure_fetches = Ref(0)
        failing = JWKSet(
            "custom://failing";
            refresh_cooldown=30,
            cache_now=failure_clock,
            fetcher=function (_)
                failure_fetches[] += 1
                failure_clock.value += 31
                error("fetch failed")
            end,
        )
        @test_throws ErrorException JWTs.refresh_for_unknown_kid!(failing, "missing")
        @test failing.last_key_miss_refresh_at == 31.0
        @test !JWTs.refresh_for_unknown_kid!(failing, "missing")
        @test failure_fetches[] == 1

        # A bogus kid may wait for I/O, but cached known-key lookup remains available.
        fetch_started = Channel{Nothing}(1)
        release_fetch = Channel{Nothing}(1)
        blocking = JWKSet(
            "custom://blocking";
            fetcher=function (_)
                put!(fetch_started, nothing)
                take!(release_fetch)
                return doc(["known"])
            end,
        )
        blocking.keys["known"] = symmetric_key
        miss_task = @async try
            JWTs.resolve_verification_key(blocking, "missing")
        catch e
            e
        end
        take!(fetch_started)
        known_task = @async JWTs.resolve_verification_key(blocking, "known")
        known_result = timedwait(() -> istaskdone(known_task), 1.0)
        put!(release_fetch, nothing)
        @test known_result == :ok
        @test fetch(known_task) === symmetric_key
        @test fetch(miss_task) isa JWTs.JWKSError

        # Explicit refreshes are serialized. A slow older response cannot overwrite
        # the result of a newer refresh that started later.
        slow_started = Channel{Nothing}(1)
        release_slow = Channel{Nothing}(1)
        serial = JWKSet("custom://serial")
        slow_task = @async refresh!(
            serial;
            fetcher=function (_)
                put!(slow_started, nothing)
                take!(release_slow)
                return doc(["stale"])
            end,
        )
        take!(slow_started)
        fresh_task = @async refresh!(
            serial;
            fetcher=_ -> doc(["fresh"]),
        )
        @test timedwait(() -> istaskdone(fresh_task), 0.1) == :timed_out
        put!(release_slow, nothing)
        fetch(slow_task)
        fetch(fresh_task)
        @test collect(keys(serial.keys)) == ["fresh"]

        # RemoteJWKSet and its embedded JWKSet share the same refresh lock. An
        # older Remote response cannot overwrite a later direct nested refresh.
        rsa_doc = JSON.parse(read(joinpath(keydir, "jwkkey.json"), String))
        remote_old = Dict("keys" => [rsa_doc["keys"][1]])
        remote_new = Dict("keys" => [rsa_doc["keys"][2]])
        remote_slow_started = Channel{Nothing}(1)
        release_remote_slow = Channel{Nothing}(1)
        nested_source = JWTs.RemoteJWKSet(
            "https://issuer.example/serialized-keys";
            fetcher=function (_)
                put!(remote_slow_started, nothing)
                take!(release_remote_slow)
                return remote_old
            end,
        )
        remote_slow_task = @async refresh!(nested_source)
        take!(remote_slow_started)
        nested_fresh_task = @async refresh!(
            nested_source.keyset;
            fetcher=_ -> remote_new,
        )
        @test timedwait(() -> istaskdone(nested_fresh_task), 0.1) == :timed_out
        put!(release_remote_slow, nothing)
        fetch(remote_slow_task)
        fetch(nested_fresh_task)
        @test collect(keys(nested_source.keyset.keys)) ==
            [remote_new["keys"][1]["kid"]]

        rm(jwks_path; force = true)

        # the cooldown is configurable, and rejects nonsense
        @test JWKSet("file:///unused"; refresh_cooldown = 0).refresh_cooldown == 0.0
        @test_throws ArgumentError JWKSet("file:///unused"; refresh_cooldown = -1)
        for invalid_seconds in (NaN, Inf, -Inf)
            @test_throws ArgumentError JWKSet(
                "file:///unused";
                refresh_cooldown=invalid_seconds,
            )
            @test_throws ArgumentError JWTs.RemoteJWKSet(
                "https://issuer.example/keys";
                ttl=invalid_seconds,
            )
            @test_throws ArgumentError JWTs.OIDCDiscovery(
                "https://issuer.example";
                metadata_ttl=invalid_seconds,
            )
        end
    end
end
