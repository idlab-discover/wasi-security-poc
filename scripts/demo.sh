#!/usr/bin/env bash
# Walk through the example policies: the same guests run under different
# ELASTIC WASI security policies, and the output shows what is allowed/denied.
#
#   ./scripts/demo.sh            # everything
#   ./scripts/demo.sh net check  # only some sections: fs env net invalid check
set -uo pipefail

cd "$(dirname "$0")/.."

SECTIONS=("$@")
[ ${#SECTIONS[@]} -eq 0 ] && SECTIONS=(fs env net invalid check)
want() { [[ " ${SECTIONS[*]} " == *" $1 "* ]]; }

if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; RED=$'\e[31m'; CYAN=$'\e[36m'; RESET=$'\e[0m'
else
  BOLD=; DIM=; GREEN=; RED=; CYAN=; RESET=
fi

echo "${DIM}building host CLI and guests...${RESET}"
cargo build --quiet --workspace || exit 1
(cd guests && cargo build --quiet --release) || exit 1

BIN=target/debug/wasmtime-elastic-wasi-security-poc
G=guests/target/wasm32-wasip2/release

# Fresh host directories the policies map into the guest.
rm -rf demo
mkdir -p demo/models demo/data
echo "v1 model weights" > demo/models/weights.txt

section() { printf '\n%s══ %s %s\n' "$BOLD" "$1" "$RESET"; }

# Run one scenario: show the policy, then the run, with verdicts coloured.
scenario() {
  local title=$1 policy=$2; shift 2
  printf '\n%s── %s%s\n' "$CYAN" "$title" "$RESET"
  if [ -n "$policy" ] && [ -f "$policy" ]; then
    printf '%s%s:%s\n' "$DIM" "$policy" "$RESET"
    grep -v '^\s*#' "$policy" | sed '/^\s*$/d; s/^/    /'
  fi
  printf '%s$ %s%s\n' "$DIM" "$*" "$RESET"
  "$@" 2>&1 | sed -E \
    -e "s/(ALLOWED|ALLOW )/${GREEN}\1${RESET}/" \
    -e "s/(DENIED|DENY )/${RED}\1${RESET}/" \
    -e "s/^(\[wasi-security\])/${DIM}\1${RESET}/" \
    -e "s/^(error:.*)/${RED}\1${RESET}/"
  printf '%s(exit %s)%s\n' "$DIM" "${PIPESTATUS[0]}" "$RESET"
}

if want fs; then
  section "Filesystem: one guest, three policies"
  scenario "no [storage]: no filesystem at all, even though --dir is passed" \
    policies/fs-none.toml $BIN run -p policies/fs-none.toml --dir demo $G/fs-probe.wasm
  scenario "/models read-only, /data read-write" \
    policies/fs-readwrite.toml $BIN run -p policies/fs-readwrite.toml $G/fs-probe.wasm
  echo "${DIM}host side: demo/data/report.txt = $(cat demo/data/report.txt)${RESET}"
  scenario "everything read-only: the previous run's file is readable, writes are refused" \
    policies/fs-readonly.toml $BIN run -p policies/fs-readonly.toml $G/fs-probe.wasm
fi

if want env; then
  section "Arguments and environment"
  scenario "policy argv + env; the policy's LOG_LEVEL beats --env LOG_LEVEL=info" \
    policies/env-args.toml $BIN run -p policies/env-args.toml -e LOG_LEVEL=info -e REGION=eu $G/env-probe.wasm extra-arg
fi

if want net; then
  section "Network: every socket address goes through the policy"
  scenario "no [network] rules: deny-by-default" \
    policies/net-none.toml $BIN run -p policies/net-none.toml $G/net-probe.wasm
  scenario "TCP server: listen on and connect to 127.0.0.1:7878 only" \
    policies/net-tcp-server.toml $BIN run -p policies/net-tcp-server.toml $G/net-probe.wasm
  scenario "TCP client: any loopback port outbound, no listening" \
    policies/net-tcp-client.toml $BIN run -p policies/net-tcp-client.toml $G/net-probe.wasm
  scenario "DNS + UDP to one peer, TCP off" \
    policies/net-udp-dns.toml $BIN run -p policies/net-udp-dns.toml $G/net-probe.wasm
  scenario "allow everything (for contrast)" \
    policies/net-allow-all.toml $BIN run -p policies/net-allow-all.toml $G/net-probe.wasm
fi

if want invalid; then
  section "Invalid policies fail closed"
  scenario "hostname in a rule: rejected before the guest is loaded" \
    policies/invalid-hostname.toml $BIN run -p policies/invalid-hostname.toml $G/net-probe.wasm
  scenario "host directory missing: the run fails instead of silently granting less" \
    policies/invalid-missing-dir.toml $BIN run -p policies/invalid-missing-dir.toml $G/fs-probe.wasm
fi

if want check; then
  section "Asking a policy without running anything"
  scenario "wasmtime-elastic-wasi-security-poc check" "" \
    $BIN check policies/net-tcp-server.toml --connect tcp://127.0.0.1:7878 --connect 10.0.0.5:5432 --bind tcp://0.0.0.0:8080
fi
