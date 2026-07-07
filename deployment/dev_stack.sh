#!/usr/bin/env bash
#
# Local development stack for 4mica-core.
#
# Brings up everything the api/sdk e2e tests need, wired together with a single
# generated .env so you never hand-edit env vars or copy contract addresses:
#
#   1. Postgres            (docker compose)
#   2. Anvil               (--hardfork prague, matches CI)
#   3. Contracts           (forge Core4MicaFullStack, deterministic address)
#   4. Migrations          (cargo run -p migration -- up)
#   5. core-service        (cargo run -p core-service, background)
#
# The on-chain BLS verification key is derived from DEV_BLS_PRIVATE_KEY via the
# `print-vk` helper, so on-chain claim/remuneration verification matches the key
# the service signs with.
#
# Usage:
#   deployment/dev_stack.sh infra     # pg + anvil + contracts + migrations (no core-service)
#   deployment/dev_stack.sh up        # infra + core-service (full stack)
#   deployment/dev_stack.sh down      # stop core + anvil (keeps postgres + data)
#   deployment/dev_stack.sh down --all# also stop/remove postgres
#   deployment/dev_stack.sh deploy    # (re)deploy contracts only
#   deployment/dev_stack.sh env       # (re)generate .env only
#   deployment/dev_stack.sh core      # run core-service in the foreground
#   deployment/dev_stack.sh status    # show what's running
#   deployment/dev_stack.sh logs [anvil|core]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEV_DIR="$REPO_ROOT/.dev"
ENV_FILE="$REPO_ROOT/.env"
ANVIL_LOG="$DEV_DIR/anvil.log"
ANVIL_PID="$DEV_DIR/anvil.pid"
CORE_LOG="$DEV_DIR/core.log"
CORE_PID="$DEV_DIR/core.pid"
DEPLOY_LOG="$DEV_DIR/deploy.log"

# ---------------------------------------------------------------------------
# Tunables (override by exporting before invoking, e.g. CORE_PORT=4000 ... up).
# ---------------------------------------------------------------------------
ANVIL_PORT="${ANVIL_PORT:-8545}"
CORE_HOST="${CORE_HOST:-0.0.0.0}"
CORE_PORT="${CORE_PORT:-3000}"
CHAIN_ID="${CHAIN_ID:-31337}"

POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-qwerty123456}"
POSTGRES_DB="${POSTGRES_DB:-core}"

# Anvil account #0 — funded deployer + 4mica operator wallet.
DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
ACCESS_MANAGER_ADMIN="${ACCESS_MANAGER_ADMIN:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
CREATE2_SALT="${CREATE2_SALT:-4mica-core-v1}"

# BLS key the service signs guarantees with; VK words are derived from it.
DEV_BLS_PRIVATE_KEY="${DEV_BLS_PRIVATE_KEY:-0x0000000000000000000000000000000000000000000000000000000000000001}"
AUTH_JWT_SECRET="${AUTH_JWT_SECRET:-asecureauthjwtsecretkey}"

# Stablecoin + validation-registry inputs for the constructor. The local stack
# deploys real ERC20 mocks (DEPLOY_MOCK_STABLECOINS) so the core service can read
# their symbol()/decimals();
STABLECOINS_COUNT="${STABLECOINS_COUNT:-1}"
TRUSTED_VALIDATION_REGISTRY="${TRUSTED_VALIDATION_REGISTRY:-0x000000000000000000000000000000000000dEaD}"

RPC_HTTP="http://127.0.0.1:${ANVIL_PORT}"
RPC_WS="ws://127.0.0.1:${ANVIL_PORT}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m ! \033[0m%s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found in PATH"; }

pid_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
start_postgres() {
  need docker
  log "Starting postgres (docker compose)…"
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" POSTGRES_DB="$POSTGRES_DB" \
    docker compose up -d pg
  ok "postgres up on 5432"
}

start_anvil() {
  need anvil
  if pid_alive "$ANVIL_PID"; then
    ok "anvil already running (pid $(cat "$ANVIL_PID"))"
    return
  fi
  log "Starting anvil on ${ANVIL_PORT} (hardfork prague)…"
  nohup anvil --hardfork prague --host 0.0.0.0 --port "$ANVIL_PORT" \
    >"$ANVIL_LOG" 2>&1 &
  echo $! >"$ANVIL_PID"
  for _ in $(seq 1 30); do
    if curl -s -X POST "$RPC_HTTP" -H 'Content-Type: application/json' \
         --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
         | grep -q anvil; then
      ok "anvil ready ($RPC_HTTP)"
      return
    fi
    sleep 0.5
  done
  cat "$ANVIL_LOG" >&2
  die "anvil failed to become ready"
}

deploy_contracts() {
  need forge
  start_anvil
  log "Deriving verification key from BLS key…"
  eval "$(BLS_PRIVATE_KEY="$DEV_BLS_PRIVATE_KEY" \
    cargo run -q -p crypto-4mica --bin print-vk)"

  log "Deploying full stack with forge…"
  (
    cd "$REPO_ROOT/contracts"
    DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" \
    ACCESS_MANAGER_ADMIN="$ACCESS_MANAGER_ADMIN" \
    DEPLOY_ENVIRONMENT=development \
    CREATE2_SALT="$CREATE2_SALT" \
    STABLECOINS_COUNT="$STABLECOINS_COUNT" DEPLOY_MOCK_STABLECOINS=true \
    TRUSTED_VALIDATION_REGISTRY="$TRUSTED_VALIDATION_REGISTRY" \
    VK_X0="$VK_X0" VK_X1="$VK_X1" VK_Y0="$VK_Y0" VK_Y1="$VK_Y1" \
      forge script script/Core4MicaFullStack.s.sol:Core4MicaFullStackScript \
        --rpc-url "$RPC_HTTP" --broadcast --via-ir -vvvv
  ) 2>&1 | tee "$DEPLOY_LOG"

  CORE4MICA_ADDR="$(grep -oP '(?<=Core4Mica: )0x[0-9a-fA-F]{40}' "$DEPLOY_LOG" | tail -1)"
  [ -n "$CORE4MICA_ADDR" ] || die "could not parse Core4Mica address from deploy log"
  ok "Core4Mica deployed at $CORE4MICA_ADDR"
  echo "$CORE4MICA_ADDR" >"$DEV_DIR/core4mica.addr"

  CLEARING_HOUSE_ADDR="$(grep -oP '(?<=ClearingHouse: )0x[0-9a-fA-F]{40}' "$DEPLOY_LOG" | tail -1)"
  [ -n "$CLEARING_HOUSE_ADDR" ] || die "could not parse ClearingHouse address from deploy log"
  ok "ClearingHouse deployed at $CLEARING_HOUSE_ADDR"
  echo "$CLEARING_HOUSE_ADDR" >"$DEV_DIR/clearinghouse.addr"
}

write_env() {
  local contract_addr clearing_house_addr
  contract_addr="$(cat "$DEV_DIR/core4mica.addr" 2>/dev/null || true)"
  [ -n "$contract_addr" ] || die "no deployed contract address found; run 'deploy' first"
  clearing_house_addr="$(cat "$DEV_DIR/clearinghouse.addr" 2>/dev/null || true)"
  [ -n "$clearing_house_addr" ] || die "no deployed ClearingHouse address found; run 'deploy' first"

  if [ -f "$ENV_FILE" ] && [ ! -f "$ENV_FILE.bak" ] && ! grep -q "Generated by deployment/dev_stack.sh" "$ENV_FILE"; then
    cp "$ENV_FILE" "$ENV_FILE.bak"
    warn "backed up your existing .env to .env.bak"
  fi

  log "Writing $ENV_FILE…"
  cat >"$ENV_FILE" <<EOF
# Generated by deployment/dev_stack.sh — do not hand-edit; rerun 'dev_stack.sh env'.

# Postgres (consumed by docker-compose.yml and the service)
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=$POSTGRES_DB
DATABASE_URL="postgres://postgres:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"

# Auth + signing
AUTH_JWT_SECRET=$AUTH_JWT_SECRET
BLS_PRIVATE_KEY="$DEV_BLS_PRIVATE_KEY"

# Ethereum / anvil
ETHEREUM_HTTP_RPC_URL="$RPC_HTTP"
ETHEREUM_WS_RPC_URL="$RPC_WS"
# Advertised to SDK clients via getPublicParams; same anvil endpoint for the local stack.
PUBLIC_ETHEREUM_HTTP_RPC_URL="$RPC_HTTP"
ETHEREUM_CHAIN_ID="$CHAIN_ID"
ETHEREUM_CONTRACT_ADDRESS="$contract_addr"
ETHEREUM_CLEARING_HOUSE_ADDRESS="$clearing_house_addr"
ETHEREUM_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY"
# Local anvil has no real finalized head; use depth-based confirmation instead.
# This reorg-able mode is unsafe for production, so it is only permitted when
# SERVER_ENVIRONMENT=development (see EthereumConfig::validate).
CONFIRMATION_MODE=depth
NUMBER_OF_BLOCKS_TO_CONFIRM=1
PAYMENT_SCAN_LOOKBACK_BLOCKS=1

# Server
SERVER_ENVIRONMENT=development
SERVER_HOST=$CORE_HOST
SERVER_PORT=$CORE_PORT

# Guarantee handling (V2 enabled on-chain by the full-stack deploy)
GUARANTEE_REQUEST_VERSION=2
TRUSTED_VALIDATION_REGISTRIES="$TRUSTED_VALIDATION_REGISTRY"
VALIDATION_HASH_CANONICALIZATION_VERSION=4MICA_VALIDATION_REQUEST_V2

# EIP-712
EIP712_NAME="4Mica"
EIP712_VERSION="1"

# Cron cadences (fast for local feedback)
CRON_JOB_SETTINGS="*/3 * * * * *"
ETHEREUM_EVENT_SCANNER_CRON="*/3 * * * * *"
HEALTH_CHECK_CRON="*/5 * * * * *"
EOF
  ok "wrote $ENV_FILE (core $contract_addr, clearinghouse $clearing_house_addr)"
}

run_migrations() {
  log "Running migrations…"
  set -a; . "$ENV_FILE"; set +a
  cargo run -q -p migration -- up
  ok "migrations applied"
}

start_core() {
  if pid_alive "$CORE_PID"; then
    ok "core-service already running (pid $(cat "$CORE_PID"))"
    return
  fi
  log "Building + starting core-service…"
  set -a; . "$ENV_FILE"; set +a
  nohup cargo run -q -p core-service >"$CORE_LOG" 2>&1 &
  echo $! >"$CORE_PID"
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:${CORE_PORT}/core/health" >/dev/null 2>&1; then
      ok "core-service ready (http://127.0.0.1:${CORE_PORT})"
      return
    fi
    if ! pid_alive "$CORE_PID"; then
      tail -n 60 "$CORE_LOG" >&2
      die "core-service exited during startup (see $CORE_LOG)"
    fi
    sleep 1
  done
  die "core-service did not become ready in time (see $CORE_LOG)"
}

stop_pid() {
  local name="$1" file="$2"
  if pid_alive "$file"; then
    log "Stopping $name (pid $(cat "$file"))…"
    kill "$(cat "$file")" 2>/dev/null || true
    rm -f "$file"
  fi
  # Belt-and-suspenders for cargo-run child processes.
  pkill -f "$name" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_infra() {
  mkdir -p "$DEV_DIR"
  start_postgres
  start_anvil
  deploy_contracts
  write_env
  run_migrations
  echo
  ok "Infra is up (pg + anvil + contracts). Run core tests with:"
  echo "    make test-core"
  echo "To also start core-service for SDK e2e tests: make dev-up  or  make core"
}

cmd_up() {
  cmd_infra
  start_core
  echo
  ok "Full stack is up. Run SDK e2e tests with:"
  echo "    make test-sdk"
}

cmd_down() {
  stop_pid core-service "$CORE_PID"
  stop_pid anvil "$ANVIL_PID"
  if [ "${1:-}" = "--all" ]; then
    log "Stopping postgres…"
    docker compose down
  else
    ok "postgres left running (use 'down --all' to stop it)"
  fi
}

cmd_status() {
  pid_alive "$ANVIL_PID" && ok "anvil: running (pid $(cat "$ANVIL_PID"))" || warn "anvil: stopped"
  pid_alive "$CORE_PID"  && ok "core:  running (pid $(cat "$CORE_PID"))"  || warn "core:  stopped"
  docker compose ps pg 2>/dev/null || true
  [ -f "$DEV_DIR/core4mica.addr" ] && ok "contract: $(cat "$DEV_DIR/core4mica.addr")"
  [ -f "$DEV_DIR/clearinghouse.addr" ] && ok "clearinghouse: $(cat "$DEV_DIR/clearinghouse.addr")"
}

cmd_logs() {
  case "${1:-core}" in
    anvil) tail -f "$ANVIL_LOG" ;;
    core)  tail -f "$CORE_LOG" ;;
    *) die "unknown log target: ${1:-} (use anvil|core)" ;;
  esac
}

mkdir -p "$DEV_DIR"
case "${1:-up}" in
  infra)  cmd_infra ;;
  up)     cmd_up ;;
  down)   shift || true; cmd_down "${1:-}" ;;
  deploy) deploy_contracts; write_env ;;
  env)    write_env ;;
  migrate) run_migrations ;;
  core)   set -a; . "$ENV_FILE"; set +a; exec cargo run -p core-service ;;
  status) cmd_status ;;
  logs)   shift || true; cmd_logs "${1:-core}" ;;
  *) die "unknown command: $1 (use up|down|deploy|env|migrate|core|status|logs)" ;;
esac
