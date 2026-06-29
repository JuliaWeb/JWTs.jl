abstract type JWTError <: Exception end

struct JWTVerificationError <: JWTError
    code::Symbol
    message::String
end
JWTVerificationError(message::AbstractString) = JWTVerificationError(:verification_failed, String(message))

struct JWTClaimError <: JWTError
    code::Symbol
    message::String
end
JWTClaimError(message::AbstractString) = JWTClaimError(:claim_invalid, String(message))

struct JWKSError <: JWTError
    code::Symbol
    message::String
end
JWKSError(message::AbstractString) = JWKSError(:jwks_error, String(message))

function Base.showerror(io::IO, err::JWTVerificationError)
    print(io, "JWT verification error ($(err.code)): ", err.message)
end

function Base.showerror(io::IO, err::JWTClaimError)
    print(io, "JWT claim error ($(err.code)): ", err.message)
end

function Base.showerror(io::IO, err::JWKSError)
    print(io, "JWKS error ($(err.code)): ", err.message)
end
