//! `wasmtime-elastic-wasi-security-poc`: a Wasmtime-CLI-style runner that
//! sandboxes each guest with an ELASTIC WASI security policy
//! (`elastic-wasi-security` crate).
//!
//! ```text
//! wasmtime-elastic-wasi-security-poc run   --policy policy.toml guest.wasm [ARGS]...
//! wasmtime-elastic-wasi-security-poc check policy.toml --connect tcp://10.0.0.5:5432 --bind 0.0.0.0:8080
//! ```

mod runner;
mod sandbox;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use elastic_wasi_security::WasiSecurity;
use wasmtime::Engine;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::sockets::SocketAddrUse;

use crate::sandbox::{Audit, SandboxSpec};

#[derive(Parser)]
#[command(
    version,
    about = "Run WebAssembly under an ELASTIC WASI security policy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a WASI component (preview 2) or core module (preview 1) under a policy.
    Run(RunArgs),
    /// Validate a policy and ask it whether given socket addresses would be allowed.
    Check(CheckArgs),
}

#[derive(Args)]
struct RunArgs {
    /// WASI security policy (TOML). Without a policy, the guest only gets the
    /// `--dir` preopens and no network.
    #[arg(short, long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Environment variable for the guest. The policy's `[env]` wins on a conflict.
    #[arg(short, long = "env", value_name = "KEY=VALUE", value_parser = parse_key_value)]
    env: Vec<(String, String)>,

    /// Host-wide preopen (read-write), `HOST[::GUEST]`. Ignored when a policy is
    /// given: a policy's storage section is exclusive.
    #[arg(long = "dir", value_name = "HOST[::GUEST]", value_parser = parse_dir)]
    dirs: Vec<(String, String)>,

    /// Do not print the sandbox summary and socket decisions to stderr.
    #[arg(short, long)]
    quiet: bool,

    /// The WebAssembly component or module to run.
    wasm: PathBuf,

    /// Arguments for the guest, appended after the policy's `arguments`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args)]
struct CheckArgs {
    /// The policy file to check.
    #[arg(value_name = "POLICY")]
    policy: PathBuf,

    /// Ask whether the guest may connect/send to `[tcp://|udp://]<ip>:<port>`.
    #[arg(long, value_name = "ADDR")]
    connect: Vec<String>,

    /// Ask whether the guest may bind/listen on `[tcp://|udp://]<ip>:<port>`.
    #[arg(long, value_name = "ADDR")]
    bind: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Run(args) => run(args),
        Command::Check(args) => check(args),
    };
    match outcome {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: RunArgs) -> Result<i32> {
    let audit = Audit {
        enabled: !args.quiet,
    };
    let bytes = std::fs::read(&args.wasm)
        .with_context(|| format!("failed to read '{}'", args.wasm.display()))?;
    let program = args
        .wasm
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.wasm.display().to_string());

    let policy = args.policy.as_deref().map(load_policy).transpose()?;
    let origin = args
        .policy
        .as_ref()
        .map_or_else(|| "(none)".to_string(), |p| p.display().to_string());
    audit.log(format!("policy   {origin}"));

    let spec = SandboxSpec {
        program,
        cli_args: args.args,
        task_env: args.env,
        fallback_dirs: args.dirs,
        policy,
        is_component: runner::is_component(&bytes),
    };
    for line in sandbox::describe(&spec) {
        audit.log(line);
    }

    let mut builder = WasiCtxBuilder::new();
    sandbox::configure(&mut builder, &spec, audit)?;

    let engine = Engine::default();
    let code = runner::run(&engine, &args.wasm, &bytes, builder)?;
    audit.log(format!("exit     {code}"));
    Ok(code)
}

fn check(args: CheckArgs) -> Result<i32> {
    let policy = load_policy(&args.policy)?;
    println!("policy   {}: OK", args.policy.display());

    let spec = SandboxSpec {
        program: "<guest>".into(),
        cli_args: vec![],
        task_env: vec![],
        fallback_dirs: vec![],
        policy: Some(policy.clone()),
        is_component: true,
    };
    for line in sandbox::describe(&spec) {
        println!("{line}");
    }

    let probes = args
        .connect
        .iter()
        .map(|a| (a, Direction::Connect))
        .chain(args.bind.iter().map(|a| (a, Direction::Bind)));
    for (raw, direction) in probes {
        for (addr, use_) in parse_probe(raw, direction)? {
            let verdict = if policy.allows_socket(addr, use_) {
                "ALLOW"
            } else {
                "DENY "
            };
            println!("{verdict}    {:<11} {addr}", sandbox::describe_use(use_).0);
        }
    }
    Ok(0)
}

fn load_policy(path: &Path) -> Result<WasiSecurity> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy '{}'", path.display()))?;
    WasiSecurity::from_toml(&raw)
}

#[derive(Clone, Copy)]
enum Direction {
    Connect,
    Bind,
}

/// `[tcp://|udp://]<ip>:<port>`, expanded to the socket uses wasmtime would check.
fn parse_probe(raw: &str, direction: Direction) -> Result<Vec<(SocketAddr, SocketAddrUse)>> {
    let (tcp, udp, addr) = match raw.split_once("://") {
        Some(("tcp", rest)) => (true, false, rest),
        Some(("udp", rest)) => (false, true, rest),
        Some((scheme, _)) => bail!("unknown protocol '{scheme}' in '{raw}'"),
        None => (true, true, raw),
    };
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid socket address '{addr}'"))?;

    let mut uses = Vec::new();
    match direction {
        Direction::Connect => {
            if tcp {
                uses.push(SocketAddrUse::TcpConnect);
            }
            if udp {
                uses.push(SocketAddrUse::UdpSend);
            }
        }
        Direction::Bind => {
            if tcp {
                uses.extend([SocketAddrUse::TcpBind, SocketAddrUse::TcpListen]);
            }
            if udp {
                uses.push(SocketAddrUse::UdpBind);
            }
        }
    }
    Ok(uses.into_iter().map(|u| (addr, u)).collect())
}

fn parse_key_value(raw: &str) -> Result<(String, String), String> {
    raw.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got '{raw}'"))
}

fn parse_dir(raw: &str) -> Result<(String, String), String> {
    Ok(match raw.split_once("::") {
        Some((host, guest)) => (host.to_string(), guest.to_string()),
        None => (raw.to_string(), raw.to_string()),
    })
}
