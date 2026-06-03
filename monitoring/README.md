# AILedger + Lodestar adherence monitoring

A portable, config-as-code Grafana bundle that makes **adherence visible**:

- **AILedger — LARP Adherence** (`dashboards/ailedger-larp.json`) — are Decision
  Events *warranted*, is the Logbook integrity-chain unbroken, what is the
  Truthsayer wave-off rate. LARP = every execution leaves a warranted record and
  you steer by that record.
- **Lodestar Fleet — GUPP Adherence** (`dashboards/lodestar-fleet-gupp.json`) —
  engine churn (workers in flight vs idle), convoy throughput, stuck/hung
  agents, and Dolt data-plane health. GUPP = find work, execute, keep the engine
  turning.

The dashboards are themselves LARP artifacts: a system that claims adherence but
can't show it is LARPing. These panels are the proof.

> **Posture note.** This bundle references internal fleet concepts (polecats,
> convoys, Dolt, GUPP/LARP). The `ailedger-detection` repo is public. The
> AILedger/LARP dashboard is public-appropriate (it visualizes the Decision
> Event substrate this package analyzes); the Lodestar/GUPP fleet dashboard is
> internal-ops. Confirm placement before this lands on public `main` — see the
> hook bead `hq-3pcp` notes.

---

## Layout

```
monitoring/
├── README.md
├── docker-compose.yml          # portable Grafana 11 stack
├── setup-datasources.sh        # renders datasources.yaml from .env (+ smoke test)
├── .env.example                # all config, safe single-ship defaults
├── dashboards/
│   ├── ailedger-larp.json      # LARP panels (PostgreSQL / decision_events)
│   └── lodestar-fleet-gupp.json# GUPP panels (Dolt/MySQL + Infinity)
└── grafana/provisioning/
    ├── datasources/
    │   ├── datasources.yaml.tmpl   # template (in git)
    │   └── datasources.yaml        # rendered (git-ignored, may hold secrets)
    ├── dashboards/dashboards.yaml  # file provider
    └── alerting/larp-gupp-alerts.yaml  # un-warranted / broken-chain / stuck / dolt-silent
```

## Quick start (per-ship)

```bash
cd monitoring
cp .env.example .env          # edit: DOLT_*, AILEDGER_PG_* (leave PG host empty to skip LARP)
./setup-datasources.sh        # render datasources.yaml + smoke-test connectivity
docker compose up -d
open http://localhost:3001    # admin / $GRAFANA_ADMIN_PASSWORD
```

On Linux, `DOLT_HOST=host.docker.internal` resolves to the ship host via the
compose `extra_hosts` mapping, so Grafana-in-Docker reaches the ship's Dolt
server on `:3307`.

## Data sources

| Datasource (uid) | Type | Backs | Source of truth |
|---|---|---|---|
| `ailedger-pg` | PostgreSQL | LARP panels | `ledger.decision_events` (+ `verify_decision_event_chain()`) |
| `dolt-beads` | MySQL | GUPP panels | Dolt beads store on `:3307` (`issues`, `events`, `dolt_log`) |
| `streams` | Infinity | fleet event feed | `events.jsonl` mounted at `/streams` |

The GUPP **core** panels run entirely on Dolt (MySQL wire protocol), so the
dashboard works with only the beads store reachable. The `events.jsonl` feed is
one collapsible panel via the Infinity plugin; if Infinity/NDJSON isn't
available, only that panel is blank.

## Panel → adherence mapping

**LARP** (`ledger.decision_events`):

| Panel | Adherence question | Definition |
|---|---|---|
| Warrant coverage | Are decisions warranted? | `output ?\| array['warrant','rationale','reason','alternatives']` |
| Un-warranted decisions | Any 2-cell-less decisions? | the complement of the above; **>0 fires an alarm** |
| Truthsayer wave-off rate | How often is warrant rejected? | `flags_raised[].flag_type` matches `wave`/`refus` |
| Integrity chain / Per-tenant verification | Logbook unbroken? | `ledger.verify_decision_event_chain(tenant)` |

> **Warrant definition is operational.** The v2 `decision_events` schema has no
> dedicated warrant column, so "warranted" is read from the `output` JSONB. If a
> first-class `warrant`/`rationale` column lands, update the four LARP queries to
> read it directly (search the dashboard JSON for `?| array`).

**GUPP** (Dolt beads):

| Panel | Adherence question | Definition |
|---|---|---|
| Active workers / Work in flight | Is the engine turning? | distinct `assignee` / count where status in `in_progress`,`hooked` |
| Ready backlog | Is work being propelled? | count where status `open` |
| Stuck agents | Anyone stalled/zombie? | `in_progress`/`hooked` with `updated_at` older than `$stuck_hours` |
| Bead throughput / created-vs-closed | Net propulsion | `events` rows `event_type` in `closed`,`created` |
| Open convoys / Convoys completed | Macro throughput | `issues.issue_type='convoy'` |
| Dolt commits (24h) / mins-since-commit / commit rate | Data-plane health | `dolt_log` |

Both dashboards filter by ship: LARP by `tenant`, GUPP by `rig` (derived from
`assignee` prefix). Cross-link buttons jump between them.

## Alerts

`grafana/provisioning/alerting/larp-gupp-alerts.yaml` provisions:

- **AILedger LARP: un-warranted decisions** (critical) — un-warranted count > 0 / 24h
- **AILedger LARP: broken Logbook integrity chain** (critical) — any tenant chain fails verify
- **GUPP: stuck agents** (warning) — beads idle >2h, sustained 10m
- **GUPP: Dolt data-plane silent** (critical) — no Dolt commits in 90m

Contact points / notification policies are environment-specific and intentionally
not provisioned. Wire them per the alerting tiers in
`docs/caird/grafana-monitoring-plan.md` (critical → ntfy/phone, warning → email).
Until then the rules still evaluate and show state under *Alerting → Alert rules*,
and the dashboard stat panels carry red thresholds so the alarms are visible.

## Fleet rollup

`DEPLOY_MODE=fleet` runs one Grafana with a datasource per ship. The dashboards
already template by `tenant` / `rig`, so a single fleet instance pointed at a
shared/aggregated store shows the whole fleet with per-ship drill-down.

Two rollup paths:

1. **Shared store (now).** Point `dolt-beads` at the town-root Dolt (the `hq`
   database already aggregates all rigs' beads). The `rig` variable then spans
   the fleet — this is the zero-extra-infra rollup and what the defaults give you.
2. **Per-ship datasources (when ships are isolated).** Add one `dolt-beads-<ship>`
   (MySQL) and one `streams-<ship>` (Infinity) block per ship in
   `datasources.yaml.tmpl`, then use Grafana's `-- Mixed --` datasource on rollup
   panels. This is the manual precursor to the **Interchange** cross-node
   coherence layer (unbuilt — see
   `docs/lodestar-lattice-federation-tower-2026-06-02.md`); when Interchange
   lands, point a single datasource at it and retire the per-ship blocks.

## Conventions

Follows `docs/caird/grafana-monitoring-plan.md`: dashboards and alert rules live
in git, provisioned on container start; no hand-clicked dashboards. Rendered
`datasources.yaml` and `.env` are git-ignored because they may hold credentials.
