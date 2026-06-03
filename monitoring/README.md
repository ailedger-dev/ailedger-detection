# AILedger monitoring

A Grafana dashboard for making **LARP adherence** visible over AILedger Decision
Events: are decisions warranted, is the Logbook integrity-chain unbroken, and
what is the Truthsayer wave-off rate.

The dashboard is itself a LARP artifact — adherence you can see.

## Dashboard

`dashboards/ailedger-larp.json` — **AILedger — LARP Adherence** (`uid: ailedger-larp`).

Panels:

- **Warrant coverage** / **Un-warranted decisions** — share of Decision Events
  that carry a warrant.
- **Truthsayer wave-off rate** — rate (and trend) of waved-off decisions.
- **Integrity chain** — Logbook hash-chain verification status, per tenant.
- **Decision-event volume vs un-warranted** — volume over time against the
  un-warranted count.
- **Recent un-warranted decisions** — the most recent gaps to triage.

## Datasource

The dashboard reads a single Postgres datasource (`uid: ailedger-pg`) pointed at
the AILedger ledger, and queries the public Decision Events schema:

```
ledger.decision_events
```

(See the project README for the Decision Event schema.) The `tenant` template
variable is populated from `SELECT DISTINCT tenant_id FROM ledger.decision_events`.

## Import

1. In Grafana, add a Postgres datasource with `uid` `ailedger-pg` pointing at
   your AILedger ledger database.
2. **Dashboards → New → Import** and upload `dashboards/ailedger-larp.json`.
3. Select your tenant from the `tenant` dropdown.

The dashboard is plain JSON — version it alongside your deployment and edit the
panels to match your Decision Event conventions.
