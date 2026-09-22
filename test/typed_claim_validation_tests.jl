module TypedClaimValidationTests
using JWTs, Test
using JWTs: JWT, JWKSymmetric, JWKSet, Verifier, sign!, verify
Base.@kwdef struct OptionalTimes
    exp::Union{Nothing,Int64} = nothing
    nbf::Union{Nothing,Int64} = nothing
    iat::Union{Nothing,Int64} = nothing
end
Base.@kwdef struct DefaultClaims
    exp::Int64 = 2000
    iss::String = "trusted"
    aud::String = "audience"
end
struct SubjectOnly
    sub::String
end
const key = JWKSymmetric("HS256", fill(UInt8(0x42),32))
const ks = JWKSet(Any[])
ks.keys["fixture"] = key
function outcome(C, payload; now=1000.0, required_claims=String[], kwargs...)
    jwt = JWT(;payload = payload isa String ? JWTs.base64url_encode(payload) : payload)
    sign!(jwt,key,"fixture")
    verifier = Verifier(C,ks;algorithms=["HS256"],now=()->now,required_claims,kwargs...)
    try
        verify(verifier,string(jwt))
        :accepted
    catch err
        err isa JWTs.JWTClaimError || rethrow()
        err.code
    end
end
@testset "Typed decoding preserves signed claim validation" begin
    for name in ("exp","nbf","iat")
        payload=Dict{String,Any}(name=>nothing)
        @test outcome(Dict{String,Any},payload) == :claim_type
        @test outcome(OptionalTimes,payload) == :claim_type
    end
    for name in ("exp","nbf","iat")
        payload=Dict{String,Any}(name=>true)
        @test outcome(Dict{String,Any},payload;now=0.0) == :claim_type
        @test outcome(OptionalTimes,payload;now=0.0) == :claim_type
    end
    expired=Dict{String,Any}("sub"=>"local-user","exp"=>999)
    @test outcome(Dict{String,Any},expired) == :token_expired
    @test outcome(SubjectOnly,expired) == :token_expired
    # Positive, absent-claim, and fail-closed required-claim controls.
    @test outcome(OptionalTimes,Dict("exp"=>1001,"nbf"=>1000,"iat"=>1000)) == :accepted
    @test outcome(OptionalTimes,Dict{String,Any}()) == :accepted
    for C in (Dict{String,Any},OptionalTimes)
        @test outcome(C,Dict{String,Any}();max_age=60) == :claim_missing
    end
    @test outcome(SubjectOnly,Dict{String,Any}()) == :malformed_payload
    @test outcome(SubjectOnly,Dict{String,Any}("sub"=>nothing)) == :malformed_payload
    @test outcome(OptionalTimes,Dict{String,Any}();required_claims=["exp"]) == :claim_missing
    @test outcome(SubjectOnly,Dict("sub"=>"local-user");required_claims=["exp"]) == :claim_missing
    for C in (Dict{String,Any},DefaultClaims)
        @test outcome(C,Dict{String,Any}();required_claims=["exp"]) == :claim_missing
        @test outcome(C,Dict{String,Any}();issuer="trusted") == :claim_missing
        @test outcome(C,Dict{String,Any}();audience="audience") == :claim_missing
        @test outcome(C,Dict{String,Any}("iss"=>nothing);issuer="trusted") == :claim_type
        @test outcome(C,Dict{String,Any}("aud"=>true);audience="audience") == :claim_type
    end
    for C in (Dict{String,Any},SubjectOnly)
        for raw in ("[]", "null", "true", "1000", "\"x\"", "{} {}", "{} true", "{} junk")
            @test outcome(C,raw) == :malformed_payload
        end
        @test outcome(C,"{\"sub\":\"local-user\",\"exp\":2000,\"exp\":999}") == :token_expired
        @test outcome(C,Dict("sub"=>"local-user","custom"=>Dict("nested"=>true));required_claims=["custom"]) == :accepted
        @test outcome(C,Dict("sub"=>"local-user","exp"=>big(10)^30)) == :accepted
    end
    for number in ("0", "-1", "9223372036854775807", "9223372036854775808", "1000000000000000000000000000000", "1.25", "1e300")
        encoded = JWTs.base64url_encode("{\"exp\":$number}")
        decoded = JWTs.decode_jwt_json_object(encoded)
        @test JWTs.claim_number(decoded,"exp") == Float64(decoded["exp"])
    end
end

end
