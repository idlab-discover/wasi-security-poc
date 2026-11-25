//! End-to-end: run the probe guests under every example policy in `policies/`
//! and assert exactly which operations are allowed and which are denied.
//!
//! The guests are built on first use (`cargo build --release` in `guests/`,
//! target wasm32-wasip2), so `cargo test` is all that is needed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

const BIN: &str = env!("CARGO_BIN_EXE_wasmtime-elastic-wasi-security-poc");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn policy(name: &str) -> String {
    repo().join("policies").join(name).display().to_string()
}

/// Build the guests once per test binary and return the directory holding them.
fn guests() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = repo().join("guests");
        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .current_dir(&dir)
            .status()
            .expect("failed to run cargo for the guests");
        assert!(
            status.success(),
            "building the guests failed (rustup target add wasm32-wasip2?)"
        );
        dir.join("target/wasm32-wasip2/release")
    })
}

fn guest(name: &str) -> String {
    guests().join(format!("{name}.wasm")).display().to_string()
}

/// The network probe binds fixed loopback ports, so its runs must not overlap.
static NETWORK: Mutex<()> = Mutex::new(());

/// A scratch working directory with the `demo/` layout the policies refer to.
struct Workdir(PathBuf);

impl Workdir {
    fn new(test: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("wasi-security-poc-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("demo/models")).unwrap();
        std::fs::create_dir_all(dir.join("demo/data")).unwrap();
        std::fs::write(dir.join("demo/models/weights.txt"), "v1 model weights\n").unwrap();
        Workdir(dir)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Parse the probes' `  VERDICT  label -> detail` lines into label -> verdict.
fn verdicts(out: &Output) -> BTreeMap<String, String> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "run failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .filter_map(|line| {
            let (verdict, rest) = line.trim().split_once(char::is_whitespace)?;
            let label = rest.trim().split(" -> ").next()?;
            Some((label.to_string(), verdict.to_string()))
        })
        .filter(|(_, v)| matches!(v.as_str(), "ALLOWED" | "DENIED" | "SKIPPED"))
        .collect()
}

#[track_caller]
fn assert_verdicts(out: &Output, expected: &[(&str, &str)]) {
    let got = verdicts(out);
    let expected: BTreeMap<String, String> = expected
        .iter()
        .map(|(v, l)| (l.to_string(), v.to_string()))
        .collect();
    assert_eq!(
        got,
        expected,
        "\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------- storage

#[test]
fn fs_no_storage_section_means_no_filesystem_even_with_dir() {
    let w = Workdir::new("fs-none");
    // --dir would grant demo/ without a policy; the policy replaces it.
    let out = w.run(&[
        "run",
        "-p",
        &policy("fs-none.toml"),
        "--dir",
        "demo",
        &guest("fs-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("DENIED", "read  /models/weights.txt"),
            ("DENIED", "write /models/tampered.txt"),
            ("DENIED", "write /data/report.txt"),
            ("DENIED", "read  /data/report.txt"),
            ("DENIED", "list  /data"),
            ("DENIED", "read  /etc/passwd"),
            ("DENIED", "read  /data/../../etc/passwd"),
            ("DENIED", "list  /"),
        ],
    );
    assert!(stderr(&out).contains("--dir ignored"));
}

#[test]
fn fs_readwrite_mount_and_readonly_models() {
    let w = Workdir::new("fs-rw");
    let out = w.run(&[
        "run",
        "-p",
        &policy("fs-readwrite.toml"),
        &guest("fs-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("ALLOWED", "read  /models/weights.txt"),
            ("DENIED", "write /models/tampered.txt"),
            ("ALLOWED", "write /data/report.txt"),
            ("ALLOWED", "read  /data/report.txt"),
            ("ALLOWED", "list  /data"),
            ("DENIED", "read  /etc/passwd"),
            ("DENIED", "read  /data/../../etc/passwd"),
            ("DENIED", "list  /"),
        ],
    );
    // The guest wrote /data; the bytes landed in the mapped host directory.
    let written = std::fs::read_to_string(w.0.join("demo/data/report.txt")).unwrap();
    assert_eq!(written, "written by the guest\n");
    assert!(!w.0.join("demo/models/tampered.txt").exists());
}

#[test]
fn fs_readonly_allows_reads_and_refuses_writes() {
    let w = Workdir::new("fs-ro");
    std::fs::write(w.0.join("demo/data/report.txt"), "from an earlier run\n").unwrap();
    let out = w.run(&["run", "-p", &policy("fs-readonly.toml"), &guest("fs-probe")]);
    assert_verdicts(
        &out,
        &[
            ("ALLOWED", "read  /models/weights.txt"),
            ("DENIED", "write /models/tampered.txt"),
            ("DENIED", "write /data/report.txt"),
            ("ALLOWED", "read  /data/report.txt"),
            ("ALLOWED", "list  /data"),
            ("DENIED", "read  /etc/passwd"),
            ("DENIED", "read  /data/../../etc/passwd"),
            ("DENIED", "list  /"),
        ],
    );
    let untouched = std::fs::read_to_string(w.0.join("demo/data/report.txt")).unwrap();
    assert_eq!(untouched, "from an earlier run\n");
}

#[test]
fn no_policy_falls_back_to_dir_preopens() {
    let w = Workdir::new("fs-dir");
    let out = w.run(&["run", "--dir", "demo/data::/data", &guest("fs-probe")]);
    let got = verdicts(&out);
    assert_eq!(got["write /data/report.txt"], "ALLOWED");
    assert_eq!(got["read  /models/weights.txt"], "DENIED");
}

#[test]
fn missing_host_directory_fails_the_run() {
    let w = Workdir::new("fs-missing");
    let out = w.run(&[
        "run",
        "-p",
        &policy("invalid-missing-dir.toml"),
        &guest("fs-probe"),
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "the guest must not start");
    assert!(stderr(&out).contains("failed to preopen read-only 'demo/does-not-exist'"));
}

// ------------------------------------------------------------ env and argv

#[test]
fn policy_sets_argv_and_env_and_wins_over_cli_env() {
    let w = Workdir::new("env");
    let out = w.run(&[
        "run",
        "-p",
        &policy("env-args.toml"),
        "-e",
        "LOG_LEVEL=info",
        "-e",
        "REGION=eu",
        &guest("env-probe"),
        "extra",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#"argv = ["env-probe.wasm", "--verbose", "--mode=batch", "extra"]"#));
    assert!(
        stdout.contains("env  LOG_LEVEL=debug"),
        "policy env must win:\n{stdout}"
    );
    assert!(stdout.contains("env  REGION=eu"));
    assert!(stdout.contains("env  TENANT=elastic-demo"));
}

// ---------------------------------------------------------------- network

#[test]
fn net_no_rules_denies_everything() {
    let _guard = NETWORK.lock().unwrap_or_else(|e| e.into_inner());
    let w = Workdir::new("net-none");
    let out = w.run(&["run", "-p", &policy("net-none.toml"), &guest("net-probe")]);
    assert_verdicts(
        &out,
        &[
            ("DENIED", "dns  lookup  localhost"),
            ("DENIED", "tcp  listen  127.0.0.1:7878"),
            ("DENIED", "tcp  connect 127.0.0.1:7878"),
            ("DENIED", "tcp  connect 127.0.0.1:9"),
            ("DENIED", "udp  bind    0.0.0.0:0"),
            ("SKIPPED", "udp  send    127.0.0.1:7979"),
            ("SKIPPED", "udp  send    127.0.0.1:9"),
        ],
    );
}

#[test]
fn net_tcp_server_only_its_own_address() {
    let _guard = NETWORK.lock().unwrap_or_else(|e| e.into_inner());
    let w = Workdir::new("net-server");
    let out = w.run(&[
        "run",
        "-p",
        &policy("net-tcp-server.toml"),
        &guest("net-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("DENIED", "dns  lookup  localhost"),
            ("ALLOWED", "tcp  listen  127.0.0.1:7878"),
            ("ALLOWED", "tcp  connect 127.0.0.1:7878"),
            ("DENIED", "tcp  connect 127.0.0.1:9"),
            ("DENIED", "udp  bind    0.0.0.0:0"),
            ("SKIPPED", "udp  send    127.0.0.1:7979"),
            ("SKIPPED", "udp  send    127.0.0.1:9"),
        ],
    );
    let log = stderr(&out);
    assert!(log.contains("ALLOW tcp listen  127.0.0.1:7878"));
    assert!(log.contains("DENY  tcp connect 127.0.0.1:9  <- no [network].connect rule matches"));
}

#[test]
fn net_tcp_client_cannot_listen() {
    let _guard = NETWORK.lock().unwrap_or_else(|e| e.into_inner());
    let w = Workdir::new("net-client");
    let out = w.run(&[
        "run",
        "-p",
        &policy("net-tcp-client.toml"),
        &guest("net-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("DENIED", "dns  lookup  localhost"),
            ("DENIED", "tcp  listen  127.0.0.1:7878"),
            // Passes the policy; nothing listens, so the OS refuses.
            ("ALLOWED", "tcp  connect 127.0.0.1:7878"),
            ("ALLOWED", "tcp  connect 127.0.0.1:9"),
            ("DENIED", "udp  bind    0.0.0.0:0"),
            ("SKIPPED", "udp  send    127.0.0.1:7979"),
            ("SKIPPED", "udp  send    127.0.0.1:9"),
        ],
    );
    assert!(
        stderr(&out)
            .contains("DENY  tcp bind    127.0.0.1:7878  <- no [network].bind rule matches")
    );
}

#[test]
fn net_udp_and_dns_without_tcp() {
    let _guard = NETWORK.lock().unwrap_or_else(|e| e.into_inner());
    let w = Workdir::new("net-udp");
    let out = w.run(&[
        "run",
        "-p",
        &policy("net-udp-dns.toml"),
        &guest("net-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("ALLOWED", "dns  lookup  localhost"),
            ("DENIED", "tcp  listen  127.0.0.1:7878"),
            ("DENIED", "tcp  connect 127.0.0.1:7878"),
            ("DENIED", "tcp  connect 127.0.0.1:9"),
            ("ALLOWED", "udp  bind    0.0.0.0:0"),
            ("ALLOWED", "udp  send    127.0.0.1:7979"),
            ("DENIED", "udp  send    127.0.0.1:9"),
        ],
    );
}

#[test]
fn net_allow_all_for_contrast() {
    let _guard = NETWORK.lock().unwrap_or_else(|e| e.into_inner());
    let w = Workdir::new("net-all");
    let out = w.run(&[
        "run",
        "-p",
        &policy("net-allow-all.toml"),
        &guest("net-probe"),
    ]);
    assert_verdicts(
        &out,
        &[
            ("ALLOWED", "dns  lookup  localhost"),
            ("ALLOWED", "tcp  listen  127.0.0.1:7878"),
            ("ALLOWED", "tcp  connect 127.0.0.1:7878"),
            ("ALLOWED", "tcp  connect 127.0.0.1:9"),
            ("ALLOWED", "udp  bind    0.0.0.0:0"),
            ("ALLOWED", "udp  send    127.0.0.1:7979"),
            ("ALLOWED", "udp  send    127.0.0.1:9"),
        ],
    );
}

// ------------------------------------------------------- invalid policies

#[test]
fn hostname_rule_is_rejected_before_the_guest_loads() {
    let w = Workdir::new("bad-host");
    let out = w.run(&[
        "run",
        "-p",
        &policy("invalid-hostname.toml"),
        &guest("net-probe"),
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        stderr(&out)
            .contains("invalid wasi_security policy: invalid socket address 'db.example.com:5432'")
    );
}

#[test]
fn check_answers_socket_questions() {
    let w = Workdir::new("check");
    let out = w.run(&[
        "check",
        &policy("net-tcp-server.toml"),
        "--connect",
        "tcp://127.0.0.1:7878",
        "--connect",
        "udp://127.0.0.1:7878",
        "--bind",
        "tcp://0.0.0.0:8080",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ALLOW    tcp connect 127.0.0.1:7878"),
        "{stdout}"
    );
    assert!(
        stdout.contains("DENY     udp send    127.0.0.1:7878"),
        "{stdout}"
    );
    assert!(
        stdout.contains("DENY     tcp bind    0.0.0.0:8080"),
        "{stdout}"
    );
}
