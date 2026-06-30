const LIBCRYPTO = OpenSSL_jll.libcrypto

const HMAC_ALGORITHMS = ("HS256", "HS384", "HS512")
const RSA_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
const EC_ALGORITHMS = ("ES256", "ES384", "ES512")
const OKP_ALGORITHMS = ("EdDSA",)
const SUPPORTED_ALGORITHMS = (HMAC_ALGORITHMS..., RSA_ALGORITHMS..., EC_ALGORITHMS..., OKP_ALGORITHMS...)
const RSA_PKCS1_PSS_PADDING = Cint(6)
const RSA_PSS_SALTLEN_DIGEST = Cint(-1)

const ED25519_PKEY_ID = Ref{Cint}(0)
const P256_GROUP_NID = Ref{Cint}(0)
const P384_GROUP_NID = Ref{Cint}(0)
const P521_GROUP_NID = Ref{Cint}(0)

@inline function openssl_digest_name(alg::AbstractString)
    alg in ("RS256", "PS256", "ES256") && return "SHA256"
    alg in ("RS384", "PS384", "ES384") && return "SHA384"
    alg in ("RS512", "PS512", "ES512") && return "SHA512"
    throw(ArgumentError("unsupported digest algorithm: $alg"))
end

is_pss_algorithm(alg::AbstractString) = alg in ("PS256", "PS384", "PS512")

@inline function ec_signature_bytes(alg::AbstractString)
    alg == "ES256" && return 32
    alg == "ES384" && return 48
    alg == "ES512" && return 66
    throw(ArgumentError("unsupported ECDSA algorithm: $alg"))
end

@inline function alg_for_curve(crv::AbstractString)
    crv == "P-256" && return "ES256"
    crv == "P-384" && return "ES384"
    crv == "P-521" && return "ES512"
    crv == "Ed25519" && return "EdDSA"
    throw(ArgumentError("unsupported JWK curve: $crv"))
end

function openssl_error(op::AbstractString)
    code = ccall((:ERR_get_error, LIBCRYPTO), Culong, ())
    if code == 0
        return ErrorException("$op failed")
    end
    buf = Vector{UInt8}(undef, 256)
    GC.@preserve buf begin
        ccall((:ERR_error_string_n, LIBCRYPTO), Cvoid, (Culong, Ptr{UInt8}, Csize_t), code, pointer(buf), Csize_t(length(buf)))
    end
    nul = findfirst(==(0x00), buf)
    last = nul === nothing ? length(buf) : nul - 1
    msg = String(buf[1:last])
    return ErrorException("$op failed: $msg")
end

@inline function clear_openssl_errors()
    ccall((:ERR_clear_error, LIBCRYPTO), Cvoid, ())
    return nothing
end

@inline function require_openssl_ok(ret::Integer, op::AbstractString)
    ret == 1 || throw(openssl_error(op))
    return nothing
end

@inline function require_openssl_nonnull(ptr::Ptr{Cvoid}, op::AbstractString)
    ptr == C_NULL && throw(openssl_error(op))
    return ptr
end

@inline function free_evp_pkey!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:EVP_PKEY_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_evp_md_ctx!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:EVP_MD_CTX_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_bio!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:BIO_free, LIBCRYPTO), Cint, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_bn!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:BN_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_rsa!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:RSA_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_ec_key!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:EC_KEY_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

@inline function free_ec_point!(ptr::Ptr{Cvoid})
    ptr == C_NULL || ccall((:EC_POINT_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

function obj_sn2nid(name::AbstractString)
    nid = ccall((:OBJ_sn2nid, LIBCRYPTO), Cint, (Cstring,), name)
    nid > 0 || throw(ArgumentError("unsupported OpenSSL object name: $name"))
    return nid
end

function ed25519_pkey_id()
    nid = ED25519_PKEY_ID[]
    nid > 0 && return nid
    nid = obj_sn2nid("ED25519")
    ED25519_PKEY_ID[] = nid
    return nid
end

function ec_group_nid(crv::AbstractString)
    if crv == "P-256"
        nid = P256_GROUP_NID[]
        nid > 0 && return nid
        nid = obj_sn2nid("prime256v1")
        P256_GROUP_NID[] = nid
        return nid
    elseif crv == "P-384"
        nid = P384_GROUP_NID[]
        nid > 0 && return nid
        nid = obj_sn2nid("secp384r1")
        P384_GROUP_NID[] = nid
        return nid
    elseif crv == "P-521"
        nid = P521_GROUP_NID[]
        nid > 0 && return nid
        nid = obj_sn2nid("secp521r1")
        P521_GROUP_NID[] = nid
        return nid
    else
        throw(ArgumentError("unsupported EC curve: $crv"))
    end
end

mutable struct OpenSSLKey
    ptr::Ptr{Cvoid}

    function OpenSSLKey(ptr::Ptr{Cvoid})
        require_openssl_nonnull(ptr, "OpenSSLKey")
        key = new(ptr)
        finalizer(key) do k
            free_evp_pkey!(k.ptr)
            k.ptr = C_NULL
        end
        return key
    end
end

Base.show(io::IO, key::OpenSSLKey) = print(io, "OpenSSLKey($(key.ptr))")

function bn_from_bytes(bytes::AbstractVector{UInt8}, op::AbstractString)
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    bn = GC.@preserve data ccall(
        (:BN_bin2bn, LIBCRYPTO),
        Ptr{Cvoid},
        (Ptr{UInt8}, Cint, Ptr{Cvoid}),
        pointer(data),
        Cint(length(data)),
        C_NULL,
    )
    return require_openssl_nonnull(bn, op)
end

function rsa_public_key(modulus::AbstractVector{UInt8}, exponent::AbstractVector{UInt8})
    n = Ptr{Cvoid}(C_NULL)
    e = Ptr{Cvoid}(C_NULL)
    rsa = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        n = bn_from_bytes(modulus, "BN_bin2bn(RSA modulus)")
        e = bn_from_bytes(exponent, "BN_bin2bn(RSA exponent)")
        rsa = ccall((:RSA_new, LIBCRYPTO), Ptr{Cvoid}, ())
        require_openssl_nonnull(rsa, "RSA_new")
        require_openssl_ok(
            ccall((:RSA_set0_key, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), rsa, n, e, C_NULL),
            "RSA_set0_key",
        )
        n = C_NULL
        e = C_NULL
        pkey = ccall((:EVP_PKEY_new, LIBCRYPTO), Ptr{Cvoid}, ())
        require_openssl_nonnull(pkey, "EVP_PKEY_new")
        require_openssl_ok(
            ccall((:EVP_PKEY_set1_RSA, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, rsa),
            "EVP_PKEY_set1_RSA",
        )
        key = OpenSSLKey(pkey)
        pkey = C_NULL
        return key
    finally
        free_bn!(n)
        free_bn!(e)
        free_evp_pkey!(pkey)
        free_rsa!(rsa)
    end
end

function ec_public_key(crv::AbstractString, x::AbstractVector{UInt8}, y::AbstractVector{UInt8})
    field_bytes = ec_signature_bytes(alg_for_curve(crv))
    length(x) == field_bytes || throw(ArgumentError("$crv x coordinate must be $field_bytes bytes"))
    length(y) == field_bytes || throw(ArgumentError("$crv y coordinate must be $field_bytes bytes"))
    ec_key = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    point_bytes = UInt8[0x04; Vector{UInt8}(x); Vector{UInt8}(y)]
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, LIBCRYPTO), Ptr{Cvoid}, (Cint,), ec_group_nid(crv))
        require_openssl_nonnull(ec_key, "EC_KEY_new_by_curve_name")
        group = ccall((:EC_KEY_get0_group, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        require_openssl_nonnull(group, "EC_KEY_get0_group")
        point = ccall((:EC_POINT_new, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), group)
        require_openssl_nonnull(point, "EC_POINT_new")
        ret = GC.@preserve point_bytes begin
            ccall(
                (:EC_POINT_oct2point, LIBCRYPTO),
                Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
                group,
                point,
                pointer(point_bytes),
                Csize_t(length(point_bytes)),
                C_NULL,
            )
        end
        require_openssl_ok(ret, "EC_POINT_oct2point")
        require_openssl_ok(
            ccall((:EC_KEY_set_public_key, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, point),
            "EC_KEY_set_public_key",
        )
        pkey = ccall((:EVP_PKEY_new, LIBCRYPTO), Ptr{Cvoid}, ())
        require_openssl_nonnull(pkey, "EVP_PKEY_new")
        require_openssl_ok(
            ccall((:EVP_PKEY_set1_EC_KEY, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key),
            "EVP_PKEY_set1_EC_KEY",
        )
        key = OpenSSLKey(pkey)
        pkey = C_NULL
        return key
    finally
        free_evp_pkey!(pkey)
        free_ec_point!(point)
        free_ec_key!(ec_key)
    end
end

function okp_public_key(crv::AbstractString, x::AbstractVector{UInt8})
    crv == "Ed25519" || throw(ArgumentError("unsupported OKP curve: $crv"))
    length(x) == 32 || throw(ArgumentError("Ed25519 public key must be 32 bytes"))
    bytes = x isa Vector{UInt8} ? x : Vector{UInt8}(x)
    pkey = GC.@preserve bytes ccall(
        (:EVP_PKEY_new_raw_public_key, LIBCRYPTO),
        Ptr{Cvoid},
        (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        ed25519_pkey_id(),
        C_NULL,
        pointer(bytes),
        Csize_t(length(bytes)),
    )
    return OpenSSLKey(pkey)
end

function read_pem_key(bytes::AbstractVector{UInt8}, private::Bool)
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    bio = Ptr{Cvoid}(C_NULL)
    try
        pkey = GC.@preserve data begin
            bio = ccall((:BIO_new_mem_buf, LIBCRYPTO), Ptr{Cvoid}, (Ptr{UInt8}, Cint), pointer(data), Cint(length(data)))
            require_openssl_nonnull(bio, "BIO_new_mem_buf")
            if private
                ccall(
                    (:PEM_read_bio_PrivateKey, LIBCRYPTO),
                    Ptr{Cvoid},
                    (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}),
                    bio,
                    C_NULL,
                    C_NULL,
                    C_NULL,
                )
            else
                ccall(
                    (:PEM_read_bio_PUBKEY, LIBCRYPTO),
                    Ptr{Cvoid},
                    (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}),
                    bio,
                    C_NULL,
                    C_NULL,
                    C_NULL,
                )
            end
        end
        pkey == C_NULL && return nothing
        return OpenSSLKey(pkey)
    finally
        free_bio!(bio)
    end
end

function load_pem_key(pem::AbstractVector{UInt8})
    clear_openssl_errors()
    key = read_pem_key(pem, true)
    key !== nothing && return key
    clear_openssl_errors()
    key = read_pem_key(pem, false)
    key !== nothing && return key
    throw(openssl_error("PEM_read_bio_PrivateKey/PEM_read_bio_PUBKEY"))
end
load_pem_key(pem::AbstractString) = load_pem_key(Vector{UInt8}(codeunits(pem)))
parse_keyfile(path::AbstractString) = load_pem_key(read(path))

function der_length_bytes(len::Integer)
    len < 0 && throw(ArgumentError("DER length cannot be negative"))
    len < 0x80 && return UInt8[len]
    bytes = UInt8[]
    n = len
    while n > 0
        pushfirst!(bytes, UInt8(n & 0xff))
        n >>= 8
    end
    return UInt8[UInt8(0x80 | length(bytes)); bytes]
end

function read_der_length(bytes::AbstractVector{UInt8}, pos::Int)
    pos <= length(bytes) || throw(ArgumentError("truncated DER length"))
    first = bytes[pos]
    pos += 1
    if first < 0x80
        return Int(first), pos
    end
    nbytes = Int(first & 0x7f)
    nbytes > 0 || throw(ArgumentError("indefinite DER length is not allowed"))
    pos + nbytes - 1 <= length(bytes) || throw(ArgumentError("truncated DER length"))
    len = 0
    for _ in 1:nbytes
        len = (len << 8) | Int(bytes[pos])
        pos += 1
    end
    return len, pos
end

function der_integer(bytes::AbstractVector{UInt8})
    i = 1
    while i < length(bytes) && bytes[i] == 0x00
        i += 1
    end
    value = Vector{UInt8}(bytes[i:end])
    isempty(value) && push!(value, 0x00)
    if value[1] >= 0x80
        pushfirst!(value, 0x00)
    end
    return UInt8[0x02; der_length_bytes(length(value)); value]
end

function fixed_width_integer(bytes::AbstractVector{UInt8}, width::Int)
    value = Vector{UInt8}(bytes)
    while length(value) > width && value[1] == 0x00
        popfirst!(value)
    end
    length(value) <= width || throw(ArgumentError("DER integer is wider than expected"))
    return UInt8[zeros(UInt8, width - length(value)); value]
end

function jose_ecdsa_to_der(signature::AbstractVector{UInt8}, width::Int)
    length(signature) == 2 * width || throw(ArgumentError("ECDSA signature must be $(2 * width) bytes"))
    r = signature[1:width]
    s = signature[(width + 1):end]
    body = UInt8[der_integer(r); der_integer(s)]
    return UInt8[0x30; der_length_bytes(length(body)); body]
end

function der_ecdsa_to_jose(signature::AbstractVector{UInt8}, width::Int)
    bytes = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
    pos = 1
    pos <= length(bytes) && bytes[pos] == 0x30 || throw(ArgumentError("ECDSA signature is not a DER sequence"))
    pos += 1
    seq_len, pos = read_der_length(bytes, pos)
    pos + seq_len - 1 == length(bytes) || throw(ArgumentError("ECDSA DER sequence length mismatch"))
    pos <= length(bytes) && bytes[pos] == 0x02 || throw(ArgumentError("missing ECDSA r integer"))
    pos += 1
    r_len, pos = read_der_length(bytes, pos)
    pos + r_len - 1 <= length(bytes) || throw(ArgumentError("truncated ECDSA r integer"))
    r = bytes[pos:(pos + r_len - 1)]
    pos += r_len
    pos <= length(bytes) && bytes[pos] == 0x02 || throw(ArgumentError("missing ECDSA s integer"))
    pos += 1
    s_len, pos = read_der_length(bytes, pos)
    pos + s_len - 1 <= length(bytes) || throw(ArgumentError("truncated ECDSA s integer"))
    s = bytes[pos:(pos + s_len - 1)]
    pos += s_len
    pos == length(bytes) + 1 || throw(ArgumentError("trailing ECDSA DER data"))
    return UInt8[fixed_width_integer(r, width); fixed_width_integer(s, width)]
end

function configure_rsa_pss!(pctx::Ptr{Cvoid}, alg::AbstractString)
    is_pss_algorithm(alg) || return nothing
    require_openssl_ok(
        ccall((:EVP_PKEY_CTX_set_rsa_padding, LIBCRYPTO), Cint, (Ptr{Cvoid}, Cint), pctx, RSA_PKCS1_PSS_PADDING),
        "EVP_PKEY_CTX_set_rsa_padding",
    )
    md = ccall((:EVP_get_digestbyname, LIBCRYPTO), Ptr{Cvoid}, (Cstring,), openssl_digest_name(alg))
    require_openssl_nonnull(md, "EVP_get_digestbyname")
    require_openssl_ok(
        ccall((:EVP_PKEY_CTX_set_rsa_mgf1_md, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pctx, md),
        "EVP_PKEY_CTX_set_rsa_mgf1_md",
    )
    require_openssl_ok(
        ccall((:EVP_PKEY_CTX_set_rsa_pss_saltlen, LIBCRYPTO), Cint, (Ptr{Cvoid}, Cint), pctx, RSA_PSS_SALTLEN_DIGEST),
        "EVP_PKEY_CTX_set_rsa_pss_saltlen",
    )
    return nothing
end

function evp_digest_sign(key::OpenSSLKey, alg::AbstractString, data::AbstractString)
    signed = Vector{UInt8}(codeunits(data))
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        # `key` must stay reachable across the whole Init/Update/Final sequence: OpenSSL
        # borrows the EVP_PKEY without taking a reference, so letting the OpenSSLKey
        # finalizer run mid-operation would free it underneath us (use-after-free).
        return GC.@preserve key begin
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            require_openssl_ok(
                ccall(
                    (:EVP_DigestSignInit_ex, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{Cvoid}),
                    mdctx,
                    pctx_ref,
                    openssl_digest_name(alg),
                    C_NULL,
                    C_NULL,
                    key.ptr,
                    C_NULL,
                ),
                "EVP_DigestSignInit_ex",
            )
            configure_rsa_pss!(pctx_ref[], alg)
            ret = GC.@preserve signed begin
                ccall(
                    (:EVP_DigestSignUpdate, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(signed),
                    Csize_t(length(signed)),
                )
            end
            require_openssl_ok(ret, "EVP_DigestSignUpdate")
            out_len = Ref{Csize_t}(0)
            require_openssl_ok(
                ccall((:EVP_DigestSignFinal, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), mdctx, Ptr{UInt8}(C_NULL), out_len),
                "EVP_DigestSignFinal",
            )
            out = Vector{UInt8}(undef, Int(out_len[]))
            ret = GC.@preserve out begin
                ccall(
                    (:EVP_DigestSignFinal, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}),
                    mdctx,
                    pointer(out),
                    out_len,
                )
            end
            require_openssl_ok(ret, "EVP_DigestSignFinal")
            resize!(out, Int(out_len[]))
            out
        end
    finally
        free_evp_md_ctx!(mdctx)
    end
end

function sign_ec(key::OpenSSLKey, alg::AbstractString, data::AbstractString)
    der = evp_digest_sign(key, alg, data)
    return der_ecdsa_to_jose(der, ec_signature_bytes(alg))
end

function sign_okp(key::OpenSSLKey, alg::AbstractString, data::AbstractString)
    alg == "EdDSA" || throw(ArgumentError("unsupported OKP algorithm: $alg"))
    signed = Vector{UInt8}(codeunits(data))
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        # See evp_digest_sign: keep `key` alive for the whole borrowed-pkey operation.
        return GC.@preserve key begin
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            require_openssl_ok(
                ccall(
                    (:EVP_DigestSignInit_ex, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{Cvoid}),
                    mdctx,
                    pctx_ref,
                    C_NULL,
                    C_NULL,
                    C_NULL,
                    key.ptr,
                    C_NULL,
                ),
                "EVP_DigestSignInit_ex",
            )
            out_len = Ref{Csize_t}(0)
            ret = GC.@preserve signed begin
                ccall(
                    (:EVP_DigestSign, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    Ptr{UInt8}(C_NULL),
                    out_len,
                    pointer(signed),
                    Csize_t(length(signed)),
                )
            end
            require_openssl_ok(ret, "EVP_DigestSign")
            out = Vector{UInt8}(undef, Int(out_len[]))
            ret = GC.@preserve signed out begin
                ccall(
                    (:EVP_DigestSign, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(out),
                    out_len,
                    pointer(signed),
                    Csize_t(length(signed)),
                )
            end
            require_openssl_ok(ret, "EVP_DigestSign")
            resize!(out, Int(out_len[]))
            out
        end
    finally
        free_evp_md_ctx!(mdctx)
    end
end

function evp_digest_verify(key::OpenSSLKey, alg::AbstractString, data::AbstractString, signature::AbstractVector{UInt8})
    signed = Vector{UInt8}(codeunits(data))
    sig = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        # See evp_digest_sign: keep `key` alive for the whole borrowed-pkey operation.
        return GC.@preserve key begin
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            require_openssl_ok(
                ccall(
                    (:EVP_DigestVerifyInit_ex, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{Cvoid}),
                    mdctx,
                    pctx_ref,
                    openssl_digest_name(alg),
                    C_NULL,
                    C_NULL,
                    key.ptr,
                    C_NULL,
                ),
                "EVP_DigestVerifyInit_ex",
            )
            configure_rsa_pss!(pctx_ref[], alg)
            ret = GC.@preserve signed begin
                ccall(
                    (:EVP_DigestVerifyUpdate, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(signed),
                    Csize_t(length(signed)),
                )
            end
            require_openssl_ok(ret, "EVP_DigestVerifyUpdate")
            verify_ret = GC.@preserve sig begin
                ccall(
                    (:EVP_DigestVerifyFinal, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(sig),
                    Csize_t(length(sig)),
                )
            end
            verify_ret == 1 && return true
            verify_ret == 0 && return false
            throw(openssl_error("EVP_DigestVerifyFinal"))
        end
    finally
        free_evp_md_ctx!(mdctx)
    end
end

function verify_ec(key::OpenSSLKey, alg::AbstractString, data::AbstractString, signature::AbstractVector{UInt8})
    der = jose_ecdsa_to_der(signature, ec_signature_bytes(alg))
    return evp_digest_verify(key, alg, data, der)
end

function verify_okp(key::OpenSSLKey, alg::AbstractString, data::AbstractString, signature::AbstractVector{UInt8})
    alg == "EdDSA" || throw(ArgumentError("unsupported OKP algorithm: $alg"))
    signed = Vector{UInt8}(codeunits(data))
    sig = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        # See evp_digest_sign: keep `key` alive for the whole borrowed-pkey operation.
        return GC.@preserve key begin
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            require_openssl_ok(
                ccall(
                    (:EVP_DigestVerifyInit_ex, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{Cvoid}),
                    mdctx,
                    pctx_ref,
                    C_NULL,
                    C_NULL,
                    C_NULL,
                    key.ptr,
                    C_NULL,
                ),
                "EVP_DigestVerifyInit_ex",
            )
            verify_ret = GC.@preserve signed sig begin
                ccall(
                    (:EVP_DigestVerify, LIBCRYPTO),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(sig),
                    Csize_t(length(sig)),
                    pointer(signed),
                    Csize_t(length(signed)),
                )
            end
            verify_ret == 1 && return true
            verify_ret == 0 && return false
            throw(openssl_error("EVP_DigestVerify"))
        end
    finally
        free_evp_md_ctx!(mdctx)
    end
end

function hmac_digest(alg::AbstractString, key::AbstractVector{UInt8}, data::AbstractString)
    bytes = Vector{UInt8}(codeunits(data))
    alg == "HS256" && return SHA.hmac_sha256(key, bytes)
    alg == "HS384" && return SHA.hmac_sha384(key, bytes)
    alg == "HS512" && return SHA.hmac_sha512(key, bytes)
    throw(ArgumentError("unsupported HMAC algorithm: $alg"))
end

function constant_time_equal(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})
    diff = xor(length(a), length(b))
    maxlen = max(length(a), length(b))
    @inbounds for i in 1:maxlen
        ai = i <= length(a) ? a[i] : 0x00
        bi = i <= length(b) ? b[i] : 0x00
        diff |= Int(xor(ai, bi))
    end
    return diff == 0
end
