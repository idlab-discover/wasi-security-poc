//! Turns an ELASTIC WASI security policy into a Wasmtime [`WasiCtxBuilder`]:
//!
//! * no policy: the `--dir` preopens apply and the guest has no network;
//! * with a policy: storage is *exclusive* (only `storage.readonly` /
//!   `storage.mount` are preopened), a preopen that fails fails the run,
//!   policy `env` wins over `--env`, and every socket address goes through
//!   [`WasiSecurity::allows_socket`].
//!
//! On top of that, every socket decision is written to an audit log so a demo
//! can show *why* the guest got what it got.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use elastic_wasi_security::{NetworkRule, NetworkRuleProtocol, WasiSecurity};
use wasmtime_wasi::sockets::SocketAddrUse;
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

/// Everything the host knows about the guest it is about to start.
pub struct SandboxSpec {
    /// argv\[0\] for the guest, normally the Wasm file name.
    pub program: String,
    /// Extra argv from the command line, appended after the policy's `arguments`.
    pub cli_args: Vec<String>,
    /// `--env` pairs. The policy's `[env]` is applied after these and wins.
    pub task_env: Vec<(String, String)>,
    /// `--dir` preopens. Only used when there is no policy.
    pub fallback_dirs: Vec<(String, String)>,
    /// The policy, if any.
    pub policy: Option<WasiSecurity>,
    /// Whether the guest is a component. Core (preview 1) modules have no sockets.
    pub is_component: bool,
}

/// Writes the sandbox configuration and every policy decision to stderr.
#[derive(Clone, Copy)]
pub struct Audit {
    pub enabled: bool,
}

impl Audit {
    pub fn log(&self, line: impl AsRef<str>) {
        if self.enabled {
            eprintln!("[wasi-security] {}", line.as_ref());
        }
    }

    fn socket(&self, addr: SocketAddr, use_: SocketAddrUse, allowed: bool) {
        if !self.enabled {
            return;
        }
        let verdict = if allowed { "ALLOW" } else { "DENY " };
        let (op, section) = describe_use(use_);
        let implicit = if is_wildcard(addr)
            && matches!(use_, SocketAddrUse::TcpBind | SocketAddrUse::UdpBind)
        {
            " (ephemeral bind)"
        } else {
            ""
        };
        let reason = if allowed {
            String::new()
        } else {
            format!("  <- no [network].{section} rule matches")
        };
        self.log(format!("{verdict} {op:<11} {addr}{implicit}{reason}"));
    }
}

/// Apply `spec` to a fresh builder. Fails if the policy asks for something the
/// host cannot grant (e.g. a directory that does not exist).
pub fn configure(builder: &mut WasiCtxBuilder, spec: &SandboxSpec, audit: Audit) -> Result<()> {
    builder.inherit_stdio();
    builder.args(&argv(spec));
    for (key, value) in env(spec) {
        builder.env(key, value);
    }

    let Some(policy) = &spec.policy else {
        for (host, guest) in &spec.fallback_dirs {
            builder
                .preopened_dir(host, guest, FsPerms::ReadWrite)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("failed to preopen '{host}' as '{guest}'"))?;
        }
        return Ok(());
    };

    // A preopen the policy asked for but that could not be granted would be a
    // silent downgrade of the workload's capabilities, so fail instead.
    for (host, guest) in &policy.storage_readonly {
        builder
            .preopened_dir(host, guest, FsPerms::ReadOnly)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to preopen read-only '{host}' as '{guest}'"))?;
    }
    for (host, guest) in &policy.storage_mount {
        builder
            .preopened_dir(host, guest, FsPerms::ReadWrite)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to mount '{host}' as '{guest}'"))?;
    }

    if !spec.is_component {
        return Ok(());
    }

    // Deny-by-default: wasmtime asks this check about every address a socket
    // is bound, listened on, connected or sent to.
    let check_policy = Arc::new(policy.clone());
    builder.socket_addr_check(move |addr, use_| {
        let allowed = check_policy.allows_socket(addr, use_);
        audit.socket(addr, use_, allowed);
        Box::pin(async move { allowed })
    });
    // Coarse switches on top: a protocol no rule mentions is switched off
    // entirely, so its sockets cannot even be created.
    builder.allow_tcp(policy.uses_tcp());
    builder.allow_udp(policy.uses_udp());
    builder.allow_ip_name_lookup(policy.allow_ip_name_lookup);

    Ok(())
}

/// The sandbox `configure` builds, one line per grant, for the audit log and `check`.
pub fn describe(spec: &SandboxSpec) -> Vec<String> {
    let mut lines = vec![format!("argv     {:?}", argv(spec))];

    let env = env(spec);
    if env.is_empty() {
        lines.push("env      (none)".into());
    }
    for (key, value) in &env {
        lines.push(format!("env      {key}={value}"));
    }

    let Some(policy) = &spec.policy else {
        for (host, guest) in &spec.fallback_dirs {
            lines.push(format!(
                "storage  rw  {host} -> {guest}  (--dir, no policy)"
            ));
        }
        if spec.fallback_dirs.is_empty() {
            lines.push("storage  (none)".into());
        }
        lines.push("network  tcp=off udp=off dns=off  (no policy)".into());
        return lines;
    };

    if !spec.fallback_dirs.is_empty() {
        lines.push("storage  --dir ignored: a policy replaces the host-wide preopens".into());
    }
    for (host, guest) in &policy.storage_readonly {
        lines.push(format!("storage  ro  {host} -> {guest}"));
    }
    for (host, guest) in &policy.storage_mount {
        lines.push(format!("storage  rw  {host} -> {guest}"));
    }
    if policy.storage_readonly.is_empty() && policy.storage_mount.is_empty() {
        lines.push("storage  (none)".into());
    }

    if !spec.is_component {
        if policy.has_network_rules() || policy.allow_ip_name_lookup {
            lines.push("network  ignored: core modules (WASI preview 1) have no sockets".into());
        } else {
            lines.push("network  (none)".into());
        }
        return lines;
    }

    lines.push(format!(
        "network  tcp={} udp={} dns={}",
        on_off(policy.uses_tcp()),
        on_off(policy.uses_udp()),
        on_off(policy.allow_ip_name_lookup),
    ));
    for rule in &policy.network_bind {
        lines.push(format!("  bind     {}", format_rule(rule)));
    }
    for rule in &policy.network_connect {
        lines.push(format!("  connect  {}", format_rule(rule)));
    }
    lines
}

fn env(spec: &SandboxSpec) -> Vec<(String, String)> {
    merge_env(
        &spec.task_env,
        spec.policy.as_ref().and_then(|p| p.env.as_ref()),
    )
}

/// argv = program name, then the policy's `arguments`, then command-line args.
///
/// The Wasm file name is prepended as argv\[0\], so the policy's first argument
/// is not mistaken for the program name and `std::env::args().skip(1)` in the
/// guest sees every policy argument.
fn argv(spec: &SandboxSpec) -> Vec<String> {
    let policy_args = spec.policy.as_ref().and_then(|p| p.arguments.as_ref());
    std::iter::once(spec.program.clone())
        .chain(policy_args.into_iter().flatten().cloned())
        .chain(spec.cli_args.iter().cloned())
        .collect()
}

/// Task env first, then the policy's env on top (the policy wins on a conflict).
fn merge_env(
    task_env: &[(String, String)],
    policy_env: Option<&std::collections::HashMap<String, String>>,
) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    let mut upsert = |key: &str, value: &str| match merged.iter_mut().find(|(k, _)| k == key) {
        Some(entry) => entry.1 = value.to_string(),
        None => merged.push((key.to_string(), value.to_string())),
    };

    for (key, value) in task_env {
        upsert(key, value);
    }
    // Sorted so the audit log and the guest see a stable order.
    let mut policy_env: Vec<_> = policy_env.into_iter().flatten().collect();
    policy_env.sort();
    for (key, value) in policy_env {
        upsert(key, value);
    }
    merged
}

pub fn format_rule(rule: &NetworkRule) -> String {
    let scheme = match rule.protocol {
        NetworkRuleProtocol::Tcp => "tcp://",
        NetworkRuleProtocol::Udp => "udp://",
        NetworkRuleProtocol::Both => "",
    };
    format!("{scheme}{}", rule.socket)
}

/// Human name of a socket use, and the policy section that governs it.
pub fn describe_use(use_: SocketAddrUse) -> (&'static str, &'static str) {
    match use_ {
        SocketAddrUse::TcpBind => ("tcp bind", "bind"),
        SocketAddrUse::TcpListen => ("tcp listen", "bind"),
        SocketAddrUse::TcpAccept => ("tcp accept", "-"),
        SocketAddrUse::TcpConnect => ("tcp connect", "connect"),
        SocketAddrUse::UdpBind => ("udp bind", "bind"),
        SocketAddrUse::UdpSend => ("udp send", "connect"),
        SocketAddrUse::UdpReceive => ("udp receive", "-"),
    }
}

fn is_wildcard(addr: SocketAddr) -> bool {
    addr.ip().is_unspecified() && addr.port() == 0
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(policy: Option<&str>) -> SandboxSpec {
        SandboxSpec {
            program: "guest.wasm".into(),
            cli_args: vec!["cli".into()],
            task_env: vec![("A".into(), "task".into()), ("B".into(), "task".into())],
            fallback_dirs: vec![],
            policy: policy.map(|p| WasiSecurity::from_toml(p).unwrap()),
            is_component: true,
        }
    }

    #[test]
    fn argv_is_program_then_policy_then_cli() {
        let s = spec(Some(r#"arguments = ["--verbose"]"#));
        assert_eq!(argv(&s), ["guest.wasm", "--verbose", "cli"]);
        assert_eq!(argv(&spec(None)), ["guest.wasm", "cli"]);
    }

    #[test]
    fn policy_env_wins() {
        let s = spec(Some("[env]\nB = \"policy\"\nC = \"policy\""));
        let env = merge_env(&s.task_env, s.policy.as_ref().unwrap().env.as_ref());
        assert_eq!(
            env,
            [
                ("A".to_string(), "task".to_string()),
                ("B".to_string(), "policy".to_string()),
                ("C".to_string(), "policy".to_string()),
            ]
        );
    }

    #[test]
    fn missing_host_dir_fails_instead_of_downgrading() {
        let s = spec(Some(r#"storage.readonly = ["/definitely/not/here::/x"]"#));
        let err = configure(&mut WasiCtxBuilder::new(), &s, Audit { enabled: false }).unwrap_err();
        assert!(format!("{err:#}").contains("failed to preopen read-only"));
    }
}
