const LIBCRYPTO = OpenSSL_jll.libcrypto

const HMAC_ALGORITHMS = ("HS256", "HS384", "HS512")
const RSA_ALGORITHMS = ("RS256", "RS384", "RS512")

@inline function openssl_digest_name(alg::AbstractString)
    alg == "RS256" && return "SHA256"
    alg == "RS384" && return "SHA384"
    alg == "RS512" && return "SHA512"
    throw(ArgumentError("unsupported RSA algorithm: $alg"))
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

function sign_rsa(key::OpenSSLKey, alg::AbstractString, data::AbstractString)
    signed = Vector{UInt8}(codeunits(data))
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
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
        return out
    finally
        free_evp_md_ctx!(mdctx)
    end
end

function verify_rsa(key::OpenSSLKey, alg::AbstractString, data::AbstractString, signature::AbstractVector{UInt8})
    signed = Vector{UInt8}(codeunits(data))
    sig = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
    mdctx = ccall((:EVP_MD_CTX_new, LIBCRYPTO), Ptr{Cvoid}, ())
    require_openssl_nonnull(mdctx, "EVP_MD_CTX_new")
    try
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
        ret = GC.@preserve sig begin
            ccall(
                (:EVP_DigestVerifyFinal, LIBCRYPTO),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                mdctx,
                pointer(sig),
                Csize_t(length(sig)),
            )
        end
        ret == 1 && return true
        ret == 0 && return false
        throw(openssl_error("EVP_DigestVerifyFinal"))
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
