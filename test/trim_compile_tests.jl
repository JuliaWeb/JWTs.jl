using Test

const _TRIM_SUPPORTED = VERSION >= v"1.12.0-rc1"
const _TRIM_PRE_RELEASE = !isempty(VERSION.prerelease)
const _JULIAC_ENTRYPOINT_EXPR = "using JuliaC; if isdefined(JuliaC, :main); JuliaC.main(ARGS); else JuliaC._main_cli(ARGS); end"

function _trim_enabled()::Bool
    return get(ENV, "JWTS_RUN_TRIM_COMPILE", "1") == "1"
end

function _trim_compile_timeout_s()::Float64
    default = Sys.isapple() ? "240.0" : "180.0"
    return parse(Float64, get(ENV, "JWTS_TRIM_COMPILE_TIMEOUT_S", default))
end

function _trim_setup_timeout_s()::Float64
    return parse(Float64, get(ENV, "JWTS_TRIM_SETUP_TIMEOUT_S", "180.0"))
end

function _trim_executable_timeout_s()::Float64
    return parse(Float64, get(ENV, "JWTS_TRIM_EXE_TIMEOUT_S", "30.0"))
end

function _package_project_path()::String
    return normpath(joinpath(@__DIR__, ".."))
end

function _juliac_project_path()::String
    return joinpath(@__DIR__, "trim")
end

function _run_command_with_timeout(cmd::Cmd; timeout_s::Float64, log_label::String)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    timed_out = false
    try
        proc = run(pipeline(ignorestatus(cmd), stdout=out, stderr=out); wait=false)
        timed_out = _wait_process_with_timeout!(proc; timeout_s=timeout_s, log_label=log_label)
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
    end
    output = try
        read(output_path, String)
    catch
        ""
    finally
        rm(output_path; force=true)
    end
    return exit_code, output, timed_out
end

function _wait_process_with_timeout!(proc::Base.Process; timeout_s::Float64, log_label::String)
    started_at = time()
    next_log_at = started_at + 10.0
    while Base.process_running(proc)
        now = time()
        if now - started_at >= timeout_s
            try
                kill(proc)
            catch
            end
            return true
        end
        if now >= next_log_at
            elapsed = round(now - started_at; digits=1)
            println("[trim] $(log_label) WAIT $(elapsed)s")
            flush(stdout)
            next_log_at = now + 10.0
        end
        sleep(0.1)
    end
    try
        wait(proc)
    catch
    end
    return false
end

function _trim_timeout_error(kind::String, script_file::String, output::String="")
    msg = "trim $kind timed out for $(script_file)"
    if !isempty(output)
        msg = string(msg, "\n---- captured output ----\n", output, "\n---- end captured output ----")
    end
    throw(ArgumentError(msg))
end

function _maybe_print_output(header::String, output::String)
    isempty(output) && return nothing
    println(header)
    println(output)
    println("---- end output ----")
    return nothing
end

function _ensure_juliac_project!(juliac_project_path::String)::Nothing
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$juliac_project_path -e "using Pkg; Pkg.instantiate()"`
    exit_code, output, timed_out = _run_command_with_timeout(cmd; timeout_s=_trim_setup_timeout_s(), log_label="setup")
    timed_out && _trim_timeout_error("setup", "test/trim/Project.toml", output)
    if exit_code != 0
        _maybe_print_output("---- trim setup output ----", output)
    end
    @test exit_code == 0
    return nothing
end

function _run_trim_compile(
    package_project_path::String,
    juliac_project_path::String,
    script_path::String,
    output_name::String;
    timeout_s::Float64=_trim_compile_timeout_s(),
    bundle_dir::Union{Nothing,String}=nothing,
)
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = if bundle_dir === nothing
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$juliac_project_path -e $(_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --project=$package_project_path --experimental --trim=safe $script_path`
    else
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$juliac_project_path -e $(_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --bundle $bundle_dir --project=$package_project_path --experimental --trim=safe $script_path`
    end
    return _run_command_with_timeout(cmd; timeout_s=timeout_s, log_label="compile")
end

function _run_trim_executable(run_cmd; timeout_s::Float64=_trim_executable_timeout_s())
    return _run_command_with_timeout(run_cmd; timeout_s=timeout_s, log_label="run")
end

function _trim_use_bundle()::Bool
    return get(ENV, "JWTS_TRIM_BUNDLE", "1") == "1"
end

function _trim_output_path(dir::String, output_name::String)::String
    path = joinpath(dir, output_name)
    isfile(path) && return path
    exe_path = joinpath(dir, "$(output_name).exe")
    isfile(exe_path) && return exe_path
    return path
end

function _parse_trim_verify_totals(output::String)
    m = match(r"Trim verify finished with\s+(\d+)\s+errors,\s+(\d+)\s+warnings\.", output)
    m === nothing && return nothing
    return parse(Int, m.captures[1]), parse(Int, m.captures[2])
end

function _count_trim_verify_messages(output::String)::Tuple{Int,Int}
    errors = length(collect(eachmatch(r"Verifier error #\d+:", output)))
    warnings = length(collect(eachmatch(r"Verifier warning #\d+:", output)))
    return errors, warnings
end

function _trim_selected_workloads(workloads::Vector{Tuple{String,String}})::Vector{Tuple{String,String}}
    only = strip(get(ENV, "JWTS_TRIM_ONLY", ""))
    isempty(only) && return workloads
    selected = Tuple{String,String}[]
    for workload in workloads
        workload[1] == only && push!(selected, workload)
    end
    isempty(selected) && throw(ArgumentError("unknown JWTS_TRIM_ONLY workload: $(only)"))
    return selected
end

function _run_trim_case(package_project_path::String, juliac_project_path::String, script_file::String, output_name::String)
    script_path = joinpath(@__DIR__, script_file)
    @test isfile(script_path)
    println("[trim] compile START $(script_file)")
    start_t = time()
    mktempdir() do tmpdir
        cd(tmpdir) do
            bundle_dir = _trim_use_bundle() ? joinpath(tmpdir, "bundle") : nothing
            exit_code, output, timed_out = _run_trim_compile(package_project_path, juliac_project_path, script_path, output_name; bundle_dir=bundle_dir)
            timed_out && _trim_timeout_error("compile", script_file, output)
            totals = _parse_trim_verify_totals(output)
            trim_errors, trim_warnings = if totals === nothing
                fallback = _count_trim_verify_messages(output)
                if exit_code == 0 && fallback == (0, 0)
                    fallback
                else
                    error("failed to parse trim verifier summary:\n$output")
                end
            else
                totals
            end
            if get(ENV, "JWTS_TRIM_PRINT_OUTPUT", "0") == "1" || trim_errors > 0 || trim_warnings > 0
                _maybe_print_output("---- trim compile output ($(script_file)) ----", output)
            end
            @test trim_errors == 0
            @test trim_warnings == 0
            run_dir = bundle_dir === nothing ? pwd() : joinpath(bundle_dir, "bin")
            run_path = _trim_output_path(run_dir, output_name)
            @test exit_code == 0
            @test isfile(run_path)
            run_cmd = `$(abspath(run_path))`
            run_exit, run_output, run_timed_out = _run_trim_executable(run_cmd)
            run_timed_out && _trim_timeout_error("executable run", script_file, run_output)
            if run_exit != 0
                _maybe_print_output("---- trim executable output ($(script_file)) ----", run_output)
            end
            @test run_exit == 0
        end
    end
    println("[trim] compile DONE $(script_file) ($(round(time() - start_t; digits=2))s)")
    return nothing
end

@testset "Trim compile" begin
    if !_trim_enabled()
        println("[trim] skip: JWTS_RUN_TRIM_COMPILE != 1")
        @test true
    elseif Sys.iswindows()
        println("[trim] skip Windows: JuliaC trim compilation is currently too slow for this package matrix")
        @test true
    elseif Sys.WORD_SIZE != 64
        println("[trim] skip non-64-bit Julia: JuliaC trim compilation is only exercised on 64-bit targets")
        @test true
    elseif !_TRIM_SUPPORTED
        println("[trim] skip Julia < 1.12: JuliaC trim compilation is unavailable")
        @test true
    elseif _TRIM_PRE_RELEASE
        println("[trim] skip prerelease Julia: trim verifier behavior is not stable yet")
        @test true
    else
        package_project_path = _package_project_path()
        juliac_project_path = _juliac_project_path()
        @test isfile(joinpath(juliac_project_path, "Project.toml"))
        _ensure_juliac_project!(juliac_project_path)
        trim_workloads = [
            ("jwt_trim_signature.jl", "jwt_trim_signature"),
            ("jwt_trim_core.jl", "jwt_trim_core"),
        ]
        for (script_file, output_name) in _trim_selected_workloads(trim_workloads)
            _run_trim_case(package_project_path, juliac_project_path, script_file, output_name)
        end
    end
end
