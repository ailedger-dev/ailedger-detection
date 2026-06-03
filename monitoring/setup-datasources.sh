#!/usr/bin/env bash
#
# setup-datasources.sh — render Grafana datasource provisioning from .env.
#
# Reads ./.env (falls back to ./.env.example), substitutes the known variables
# into grafana/provisioning/datasources/datasources.yaml.tmpl, and writes
# grafana/provisioning/datasources/datasources.yaml (git-ignored, may hold
# rendered credentials).
#
# It then optionally smoke-tests the Dolt (MySQL) and AILedger (PostgreSQL)
# datasources if the matching client is installed, so misconfiguration surfaces
# before Grafana starts rather than as a silent "No data" panel.
#
# Usage:
#   ./setup-datasources.sh            # render + smoke-test
#   ./setup-datasources.sh --no-test  # render only
set -euo pipefail

cd "$(dirname "$0")"

TMPL="grafana/provisioning/datasources/datasources.yaml.tmpl"
OUT="grafana/provisioning/datasources/datasources.yaml"
DO_TEST=1
[[ "${1:-}" == "--no-test" ]] && DO_TEST=0

# ── Load config ───────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
  ENV_FILE=.env
elif [[ -f .env.example ]]; then
  echo "warn: no .env found; using .env.example defaults" >&2
  ENV_FILE=.env.example
else
  echo "error: no .env or .env.example found" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

# Variables referenced by the template. envsubst is restricted to this list so a
# stray '$' elsewhere is left untouched.
VARS='$SHIP_NAME $AILEDGER_PG_HOST $AILEDGER_PG_PORT $AILEDGER_PG_DATABASE'
VARS+=' $AILEDGER_PG_USER $AILEDGER_PG_PASSWORD $AILEDGER_PG_SSLMODE'
VARS+=' $DOLT_HOST $DOLT_PORT $DOLT_DATABASE $DOLT_USER $DOLT_PASSWORD'

if ! command -v envsubst >/dev/null 2>&1; then
  echo "error: envsubst not found (install gettext)" >&2
  exit 1
fi

# ── Render ────────────────────────────────────────────────────────────────────
envsubst "$VARS" < "$TMPL" > "$OUT"
echo "rendered $OUT (ship=${SHIP_NAME:-?}, mode=${DEPLOY_MODE:-ship})"

if [[ -z "${AILEDGER_PG_HOST:-}" ]]; then
  echo "note: AILEDGER_PG_HOST is empty — AILedger (LARP) datasource will not connect; LARP panels show 'No data'." >&2
fi

# ── Smoke tests (best-effort) ─────────────────────────────────────────────────
if [[ "$DO_TEST" -eq 1 ]]; then
  if command -v mysql >/dev/null 2>&1; then
    if mysql -h "${DOLT_HOST/host.docker.internal/127.0.0.1}" -P "${DOLT_PORT}" \
        -u "${DOLT_USER}" ${DOLT_PASSWORD:+-p"${DOLT_PASSWORD}"} \
        -e "SELECT 1" "${DOLT_DATABASE}" >/dev/null 2>&1; then
      echo "ok: Dolt/beads reachable at ${DOLT_HOST}:${DOLT_PORT}/${DOLT_DATABASE}"
    else
      echo "warn: could not reach Dolt at ${DOLT_HOST}:${DOLT_PORT} (GUPP panels need it)" >&2
    fi
  else
    echo "skip: mysql client not installed; cannot smoke-test Dolt" >&2
  fi

  if [[ -n "${AILEDGER_PG_HOST:-}" ]] && command -v psql >/dev/null 2>&1; then
    if PGPASSWORD="${AILEDGER_PG_PASSWORD}" psql \
        "host=${AILEDGER_PG_HOST} port=${AILEDGER_PG_PORT} dbname=${AILEDGER_PG_DATABASE} user=${AILEDGER_PG_USER} sslmode=${AILEDGER_PG_SSLMODE}" \
        -c "SELECT 1" >/dev/null 2>&1; then
      echo "ok: AILedger PostgreSQL reachable at ${AILEDGER_PG_HOST}:${AILEDGER_PG_PORT}"
    else
      echo "warn: could not reach AILedger PostgreSQL (LARP panels need it)" >&2
    fi
  fi
fi

echo "done. Next: docker compose up -d"
