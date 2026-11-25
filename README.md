# wasi-security PoC

A Wasmtime-CLI-style runner that sandboxes every guest with an
[ELASTIC WASI security policy](https://github.com/elasticproject-eu/wasi-security)
(`elastic-wasi-security` crate). It ships with probe guests and example policies,
so you can see which operations each policy allows and which it denies.



## Quick start

```bash
rustup target add wasm32-wasip2      # guests are WASI preview 2 components
./scripts/demo.sh                    # builds everything and walks through every policy
./scripts/demo.sh net                # just one section: fs env net invalid check
cargo test                           # asserts the full allow/deny matrix below
```

## CLI

```text
wasmtime-elastic-wasi-security-poc run   [-p POLICY.toml] [-e KEY=VALUE]... [--dir HOST[::GUEST]]...
                                         [-q] GUEST.wasm [ARGS]...
wasmtime-elastic-wasi-security-poc check POLICY.toml [--connect ADDR]... [--bind ADDR]...
```

- `run` accepts WASI p2 components (full policy) and p1 core modules
  (`arguments`, `env`, `storage` only, since p1 has no sockets). The guest's
  exit code is passed through.
- On stderr, `run` prints the sandbox it built and an `ALLOW`/`DENY` line for
  every socket address Wasmtime asks the policy about. `-q` silences this.
- `check` parses a policy and answers questions like "may the guest connect to
  `10.0.0.5:5432`?" without running anything. `ADDR` is `[tcp://|udp://]ip:port`.

Example (stderr lines are prefixed `[wasi-security]`):

```text
$ wasmtime-elastic-wasi-security-poc run -p policies/net-tcp-server.toml net-probe.wasm
[wasi-security] network  tcp=on udp=off dns=off
[wasi-security]   bind     tcp://127.0.0.1:7878
[wasi-security]   connect  tcp://127.0.0.1:7878
net-probe: what can this guest reach?
  DENIED   dns  lookup  localhost -> Uncategorized: failed to lookup address information: Non-recoverable error
[wasi-security] ALLOW tcp bind    127.0.0.1:7878
[wasi-security] ALLOW tcp listen  127.0.0.1:7878
  ALLOWED  tcp  listen  127.0.0.1:7878 -> bound 127.0.0.1:7878
[wasi-security] ALLOW tcp bind    0.0.0.0:0 (ephemeral bind)
[wasi-security] ALLOW tcp connect 127.0.0.1:7878
[wasi-security] ALLOW tcp accept  127.0.0.1:41862
  ALLOWED  tcp  connect 127.0.0.1:7878 -> accepted 127.0.0.1:41862, server read "ping"
[wasi-security] ALLOW tcp bind    0.0.0.0:0 (ephemeral bind)
[wasi-security] DENY  tcp connect 127.0.0.1:9  <- no [network].connect rule matches
  DENIED   tcp  connect 127.0.0.1:9 -> PermissionDenied: Permission denied (os error 2)
  DENIED   udp  bind    0.0.0.0:0 -> PermissionDenied: Permission denied (os error 2)
```

