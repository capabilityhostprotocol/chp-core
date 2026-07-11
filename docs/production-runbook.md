# Production Runbook

Running CHP hosts and gateways in production: posture, operations, and
recovery. Applies to the Python reference implementation (the TS host is a
conformance fixture, not a production target). Everything here is additive
configuration — the local-first defaults are unchanged.

## Posture

**Auth.** Set `CHP_HOST_REQUIRE_AUTH=1` in every production unit: the host
refuses to start with no API keys configured (a misconfigured deploy fails
loudly at boot instead of serving open). Configure per-caller keys —
`CHP_HOST_API_KEYS="agent-a:key1,steward:key2[:scope1|scope2]"` — so evidence
carries *verified* subjects; the shared `CHP_HOST_API_KEY` is the anonymous
fallback.

**Key rotation (no downtime).** The same caller name may carry several keys
simultaneously: `agent-a:NEWKEY,agent-a:OLDKEY`. Rotation is add-new → drain
callers onto the new key → remove-old. Every entry is compared in constant
time.

**TLS.** The reference server is deliberately plain HTTP: terminate TLS in
front of it (reverse proxy, ingress, or a private mesh network such as
Tailscale — network-layer confidentiality MAY substitute per the binding §2).
Do not expose a CHP port directly to the public internet.

**Secrets.**
- macOS: `chp-host serve --secrets-from-keychain KEY1 KEY2` (Keychain service
  `com.chp.secrets`).
- Linux/systemd: `EnvironmentFile` (mode 0600, owned by the service user).
- Docker: compose `environment:` from a 0600 `.env` file.
Host signing keys live in `~/.chp/keys/` (0700 dir, 0600 private key,
plaintext — filesystem permissions are the custody boundary; plan
accordingly on shared machines).

## Reliability knobs

| Knob | Default | Production note |
|---|---|---|
| `CHP_STORE_BUSY_TIMEOUT_MS` | 5000 | Multi-writer wait; finite on purpose |
| `CHP_DRAIN_TIMEOUT_S` | 10 | SIGTERM drain window (streams are capped by it) |
| `CHP_ROUTER_DISCOVER_TIMEOUT` | 5 | Per-member catalog probe timeout |
| `CHP_HOST_MAX_BODY_BYTES` | 8 MiB | Request-body cap |
| `CHP_HTTP_LOG` | off | `1` = access log to stderr |
| mesh remote `timeout_s` | 30 | Per-member transport timeout |
| mesh remote `retries` | 0 | Opt-in client retry — a mid-flight drop may have EXECUTED (at-most-once is not guaranteed on that path); keep 0 for non-idempotent capabilities |
| `gateway.probe_interval_s` | off | Continuous health probing (§11 evidence) |
| `gateway.witness_interval_s` | off | Mesh witnessing loop (§12) |
| `gateway.retention_interval_s` + `retention_config` | off | Scheduled retention |

## Shutdown & upgrade

**SIGTERM drains.** The server stops accepting, waits for in-flight requests
up to `CHP_DRAIN_TIMEOUT_S`, then exits 0. systemd units ship
`KillSignal=SIGTERM` + `TimeoutStopSec=15`; compose services ship
`stop_grace_period: 15s`. SIGINT (Ctrl-C) is unchanged.

**Single-node upgrade.** `chp-host update [--version X] [--require-provenance]`
pip-upgrades then restarts the node's services (launchd / systemd user+system
/ container pid-1 — the container path relies on `restart: unless-stopped`).
`--require-provenance` refuses to install any wheel whose publisher-signed
statement does not verify (spec §9) — atomic: all verify or nothing installs.

**Rolling mesh upgrade.** One node at a time, health-gated:
```
for node in $(chp-host mesh list --urls); do
  # governed: invoke chp.adapters.host.update on the node (or ssh chp-host update)
  # then WAIT for the new version before touching the next node:
  until curl -fsS $node/health | grep -q '"host_version": "X.Y.Z"'; do sleep 5; done
done
```
The gateway's failover covers the node being restarted; never restart two
owners of the same capability at once. Verify with the wire suite when in
doubt: `python conformance/runner.py --url $node --key $KEY --suite wire`.

## Backup & restore

**Never `cp` a live store** — a WAL database copied mid-write is torn. Use
the online backup:
```
chp store backup /backups/evidence-$(date +%F).sqlite --store .chp/evidence.sqlite --verify
```
`--verify` re-runs chain verification on every correlation IN THE COPY and
exits 1 on any break — a backup that fails verification is an incident
(see monitoring). Restore = stop the host, put the copy in place, start;
then `GET /verify/<correlation>` spot-checks. Sidecars to include in backups:
`~/.chp/keys/` (custody!), `~/.chp/witnesses/`, `~/.chp/revocations/`,
`~/.chp/mesh.json`.

## Key compromise runbook

In order, fastest mitigation first:

1. **Revoke live mandates** the compromised key issued:
   `chp mandate revoke <mandate.json> --push <every enforcing host>` — the
   issuer-only statement lands in each host's `/revocations` set and gate 5
   denies from the next invocation (spec §10 Revocation).
2. **Rotate the host key**: `chp rotate-key` (spec §3.2 continuity statement
   chains old→new so verifiers can follow).
3. **Revoke the old key**: `chp revoke-key` — self-signed revocation served in
   the identity document and `GET /revocations`.
4. **Re-anchor** if anchors referenced the old key (domain `.well-known`,
   DID anchor via `chp anchor-did`).
5. Rotate transport API keys via the overlap mechanism (Posture above).
6. Audit: `chp witness verify --store <db>` against peers' countersignatures
   — did history change while the key was compromised?

## Monitoring

Scrape `GET /metrics` (Prometheus text). Families worth alerting on:

| Metric | Alert when |
|---|---|
| `chp_http_internal_errors_total` | increases — unhandled server exceptions (bugs the evidence store never saw) |
| `chp_chain_breaks_total` | > 0 — evidence chain integrity failure |
| `chp_router_unreachable_denials_total` | rate spike — mesh reachability |
| `chp_router_unhealthy_hosts` | > 0 for sustained periods |
| `chp_store_size_bytes` | nearing disk budget → schedule retention |
| `chp_witness_last_issued_timestamp_seconds` | stale vs `witness_interval_s` — the witness loop died |
| `chp_revocations_held_total{kind}` | unexpected growth — someone is revoking |
| `chp_invocations_duration_ms_p95` | latency regressions |

What never reaches the evidence store (crashes, startup failures) goes to
stderr: `~/.chp/logs/<host_id>.err` under launchd, the journal under systemd.
`CHP_HTTP_LOG=1` adds an access log when debugging.

## Incident debugging

1. `GET /replay/<correlation_id>` — the governed record of what happened.
2. `GET /verify/<correlation_id>` — is the chain intact?
3. `/metrics` internal-errors counter — did anything escape governance?
4. stderr log — what never became an invocation.
5. For cross-host flows, replay through the GATEWAY — it stitches member
   chains and its own routing evidence (§11) into one timeline.
