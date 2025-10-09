# JWTs

[![Build Status](https://github.com/JuliaWeb/JWTs.jl/workflows/CI/badge.svg)](https://github.com/JuliaWeb/JWTs.jl/actions?query=workflow%3ACI+branch%3Amaster)
[![codecov](https://codecov.io/gh/JuliaWeb/JWTs.jl/branch/master/graph/badge.svg?token=VK7JZ2hMQx)](https://codecov.io/gh/JuliaWeb/JWTs.jl)

JSON Web Tokens (JWT) are an open, industry standard [RFC 7519](https://tools.ietf.org/html/rfc7519) method for representing and transferring claims securely between two parties.

## Keys and Key Sets

**JWK** represents a JWK Key (either for signing or verification). JWK can be either a **JWKRSA** or **JWKSymmetric**. A RSA key can represent either the public or private key. Ref: https://datatracker.ietf.org/doc/html/rfc7517

**JWKSet** holds a set of keys, fetched from a OpenId key URL, each key identified by a key id. The OpenId key URL is usually found in the OpenId configuration (e.g. `jwks_uri` element in <https://accounts.google.com/.well-known/openid-configuration>).

To create or verify JWT, using a JWKSet is preferred as it provides mechanism of dealing with key rotation. To refresh a JWKSet, or to load keys for the first time, call the `refresh!` method on it.

```julia
julia> using JWTs

julia> keyset = JWKSet("https://www.googleapis.com/oauth2/v3/certs")
JWKSet 0 keys (https://www.googleapis.com/oauth2/v3/certs)

julia> refresh!(keyset)

julia> keyset
JWKSet 2 keys (https://www.googleapis.com/oauth2/v3/certs)

julia> for (k,v) in keyset.keys
           println("    ", k, " => ", v.key)
       end
    7978a91347261a291bd71dcab4a464be7d279666 => MbedTLS.RSA(Ptr{MbedTLS.mbedtls_rsa_context} @0x0000000001e337e0)
    8aad66bdefc1b43d8db27e65e2e2ef301879d3e8 => MbedTLS.RSA(Ptr{MbedTLS.mbedtls_rsa_context} @0x0000000001d77390)
```

While symmetric keys for signing can simply be read from a jwk file into a `JWKSet`, creating a JWKSet for asymmetric key signing needs to be done by the calling code. The process may vary depending on where the private key is stored, but as an example below is a snippet of code that picks up private keys from file corresponding to each key in a jwk file.

```julia
keyset = JWKSet(keyset_url)
refresh!(keyset)
signingkeyset = deepcopy(keyset)
for k in keys(signingkeyset.keys)
    signingkeyset.keys[k] = JWKRSA(signingkeyset.keys[k].kind, MbedTLS.parse_keyfile(joinpath(dirname(keyset_url), "$k.private.pem")))
end
```

The `alg` method on a JWK returns the algorithm used for the key.

```julia
julia> JWTs.alg(keyset.keys["7978a91347261a291bd71dcab4a464be7d279666"])
"RS256"
```

## Tokens

**JWT** represents a JSON Web Token containing the payload at the minimum. When signed, it holds the header (with key id and algorithm used) and signature too. The parts are stored in encoded form.

```julia
julia> using JSON

julia> using JWTs

julia> payload = JSON.parse("""{
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
       }""");

julia> jwt = JWT(; payload=payload)
eyJuYW1lIjoiRXhhbXBsZSBVc2VyIiwiZXhwIjoxNTM2MDgwNjUxLCJhdWQiOiJleGFtcGxlLWF1ZGllbmNlIiwic3ViIjoiQ2hVeGpmZ3NhamZ1cmpzamR1dDA0ODM2NzJrZGhnc3RneTI4M2pzc1pRIiwiaWF0IjoxNTM1OTk0MjUxLCJpc3MiOiJodHRwczovL2F1dGgyLmp1bGlhY29tcHV0aW5nLmlvL2RleCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiMjIyMjIyLUctSkpKSkpKSkpKSkpKSiIsIm5vbmNlIjoiMTc3Nzc3Nzc3Nzc3N2FhYWFhYWFhYWJiYmJiYmJiYmIiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ
```

A JWT can be signed using the `sign!` method, passing a key set and a key id to sign it with.

```julia
julia> issigned(jwt)
false

julia> keyset = JWKSet("file:///my/secret/location/jwkkey.json");

julia> refresh!(keyset)

julia> keyid = first(first(keyset.keys)) # using the first key in the key set
"4Fytp3LfBhriD0eZ-k3aNS042bDiCZXg6bQNJmYoaE"

julia> sign!(jwt, keyset, keyid)

julia> issigned(jwt)
true

julia> jwt # note the additional header and signature
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjRGeXRwM0xmQmhyaUQwZVotazNhTlMwNDJiRGlDWlhnNmJRTkptWW9hRSJ9.eyJuYW1lIjoiRXhhbXBsZSBVc2VyIiwiZXhwIjoxNTM2MDgwNjUxLCJhdWQiOiJleGFtcGxlLWF1ZGllbmNlIiwic3ViIjoiQ2hVeGpmZ3NhamZ1cmpzamR1dDA0ODM2NzJrZGhnc3RneTI4M2pzc1pRIiwiaWF0IjoxNTM1OTk0MjUxLCJpc3MiOiJodHRwczovL2F1dGgyLmp1bGlhY29tcHV0aW5nLmlvL2RleCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiMjIyMjIyLUctSkpKSkpKSkpKSkpKSiIsIm5vbmNlIjoiMTc3Nzc3Nzc3Nzc3N2FhYWFhYWFhYWJiYmJiYmJiYmIiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.zfq-DT4Ft_MSU34pwFrMaealWGs0j7Ynhs9iKjf5Uf4
```

The `kid` method shows the key id used to sign a JWT. This is useful while validating a JWT.

```julia
julia> kid(jwt)
"4Fytp3LfBhriD0eZ-k3aNS042bDiCZXg6bQNJmYoaE"
```

The `alg` method shows the algorithm used to sign a JWT.

```julia
julia> alg(jwt)
"RS256"
```

## Validation

To validate a JWT against a key, call the `validate!` method, passing a key set and the key id to use.

The `isvalid` method can be used to check if a JWT is valid (or has been validated at all). It returns `nothing` if validation has not been attempted and a `Bool` indicating validity if it has been validated earlier.

```julia
julia> isvalid(jwt2)

julia> validate!(jwt, keyset, keyname)
true

julia> isvalid(jwt)
true
```

The `with_valid_jwt` method can be used to Run `f` with a valid JWT. The validated JWT is passed as an argument to `f`. If the JWT is invalid, an `ArgumentError` is thrown.

```julia
julia> with_valid_jwt(jwt2, keyset) do valid_jwt
           @info("claims", claims(valid_jwt))
       end
┌ Info: claims
│   claims(valid_jwt) =
│    Dict{String, Any} with 10 entries:
│      "name"           => "Example User"
│      "exp"            => 1536080651
│      "aud"            => "example-audience"
...
└      "email"          => "user@example.com"
```

Both `validate!` and `with_valid_jwt` methods can optionally take an `algorithms` argument, which is a list of algorithms to validate against. If the JWT's algorithm is not in the list, the validation will fail.

```julia
julia> validate!(jwt, keyset, keyname; algorithms=["RS256"])
true
```
