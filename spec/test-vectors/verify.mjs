// Non-Python verifier for CHP signed evidence bundles (chp-stable-v1).
//
// Proves the signing moat is a PROTOCOL, not a Python detail: this script
// verifies a Python-signed bundle using ONLY the chp-stable-v1 byte rules from
// spec/chp-v0.2.md + Node's stdlib crypto — no chp_core import.
//
//   node verify.mjs signed-bundle.json
//
// Exit 0 = valid; exit 1 = invalid/tampered.

import { readFileSync } from "node:fs";
import { createHash, verify as edVerify, createPublicKey } from "node:crypto";

// chp-stable-v1: reproduce Python json.dumps(obj, sort_keys=True) EXACTLY —
// separators ", " and ": " (spaces), ensure_ascii=True (\uXXXX for non-ASCII),
// recursive key sort. This is the whole ballgame for cross-language interop.
function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(v);
  if (typeof v === "string") return encodeStr(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(", ") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => encodeStr(k) + ": " + canon(v[k])).join(", ") + "}";
}
function encodeStr(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else if (c < 0x7f) out += ch;
    else if (c <= 0xffff) out += "\\u" + c.toString(16).padStart(4, "0");     // ensure_ascii
    else { // surrogate pair
      const cc = c - 0x10000;
      const hi = 0xd800 + (cc >> 10), lo = 0xdc00 + (cc & 0x3ff);
      out += "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0");
    }
  }
  return out + '"';
}
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function contentHash(ev, prevHash) {
  const corr = ev.correlation || {};
  const stable = {
    event_id: ev.event_id, event_type: ev.event_type, invocation_id: ev.invocation_id,
    capability_id: ev.capability_id, host_id: ev.host_id,
    correlation_id: typeof corr === "object" ? (corr.correlation_id ?? null) : null,
    timestamp: ev.timestamp, outcome: ev.outcome ?? null, payload: ev.payload ?? {},
    prev_hash: prevHash ?? null,
  };
  return sha256hex(canon(stable));
}

const input = JSON.parse(readFileSync(process.argv[2] || "signed-bundle.json", "utf8"));

function verifyOne(bundle) {
let prev = null, ok = true;
const h = createHash("sha256");
for (const ev of bundle.events) {
  const recomputed = contentHash(ev, ev.prev_hash ?? null);
  if (recomputed !== ev.content_hash) { console.error(`content_hash mismatch on ${ev.event_id}`); ok = false; }
  if ((ev.prev_hash ?? null) !== prev) { console.error(`chain break at ${ev.event_id}`); ok = false; }
  prev = ev.content_hash;
  h.update(ev.content_hash + "\n");                 // root = SHA256 over content_hashes joined by \n
}
const root = h.digest("hex");
if (root !== bundle.root_hash) { console.error("root_hash mismatch"); ok = false; }

if (bundle.assurance === "signed") {
  // Wrap the raw 32-byte public key in SPKI DER so Node's crypto can consume it.
  const raw = Buffer.from(bundle.public_key, "base64");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const pub = createPublicKey({ key: spki, format: "der", type: "spki" });
  const verifyCanon = (obj, sigB64) =>
    edVerify(null, Buffer.from(canon(obj), "utf8"), pub, Buffer.from(sigB64, "base64"));

  // Signature is over the canonical HEADER (origin/time/scheme + root_hash), not
  // bare root_hash — so a relabelled host_id breaks it.
  const header = { host_id: bundle.host_id, protocol_version: bundle.protocol_version,
                   created_at: bundle.created_at, canonicalization: bundle.canonicalization,
                   root_hash: bundle.root_hash };
  if (!verifyCanon(header, bundle.signature.signature)) { console.error("signature INVALID"); ok = false; }

  // Host-identity attestation: the key must self-assert this host_id + public_key.
  const att = bundle.host_identity;
  if (att) {
    // Conditional-anchors rule (spec §3 Anchors): "anchors" is in the signed
    // bytes only when present — omit-when-empty keeps pre-anchor bundles
    // byte-identical, and makes anchor strip/staple break the signature.
    const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                    valid_from: att.valid_from, valid_until: att.valid_until,
                    ...("anchors" in att ? { anchors: att.anchors } : {}) };
    // Temporal validity: created_at within [valid_from, valid_until] (ISO-8601 UTC
    // strings compare lexicographically; null = unbounded).
    const c = bundle.created_at;
    const temporalOk = (att.valid_from == null || c == null || att.valid_from <= c)
                    && (att.valid_until == null || c == null || c <= att.valid_until);
    const bound = att.host_id === bundle.host_id && att.public_key === bundle.public_key
                  && temporalOk && verifyCanon(claim, att.signature);
    if (!bound) { console.error("host_identity attestation INVALID"); ok = false; }
  }
}
return ok;
}

let ok;
if (input.kind === "adapter-provenance") {
  // Supply-chain provenance (chp-v0.2.md §9): the publisher key signs the
  // canonical header; the attestation says WHO (anchors ride inside it).
  const pub = input.publisher ?? {};
  const aggPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                        Buffer.from(pub.public_key ?? "", "base64")]),
    format: "der", type: "spki",
  });
  const vCanon = (obj, sigB64) =>
    edVerify(null, Buffer.from(canon(obj), "utf8"), aggPub, Buffer.from(sigB64, "base64"));
  const header = { kind: input.kind, package: input.package, version: input.version,
                   wheel_sha256: input.wheel_sha256, created_at: input.created_at,
                   canonicalization: input.canonicalization };
  ok = input.signature?.algorithm === "ed25519" && vCanon(header, input.signature.signature);
  const att = pub.host_identity;
  if (att) {
    const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                    valid_from: att.valid_from, valid_until: att.valid_until,
                    ...("anchors" in att ? { anchors: att.anchors } : {}) };
    if (!(att.host_id === pub.host_id && att.public_key === pub.public_key
          && vCanon(claim, att.signature))) { console.error("publisher attestation INVALID"); ok = false; }
  } else { console.error("provenance statement missing publisher attestation"); ok = false; }
  console.log(ok
    ? `VALID (adapter-provenance, ${input.package}==${input.version}, published by ${pub.host_id})`
    : "INVALID");
} else if (input.kind === "chain-witness") {
  // Chain witness (chp-v0.2.md §12): a peer's key signs the canonical header
  // — a countersignature over another host's store head at a sequence.
  const w = input.witness ?? {};
  const wPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                        Buffer.from(w.public_key ?? "", "base64")]),
    format: "der", type: "spki",
  });
  const vCanon = (obj, sigB64) =>
    edVerify(null, Buffer.from(canon(obj), "utf8"), wPub, Buffer.from(sigB64, "base64"));
  const header = { kind: input.kind, host_id: input.host_id, sequence: input.sequence,
                   store_head: input.store_head, witnessed_at: input.witnessed_at,
                   canonicalization: input.canonicalization };
  ok = input.signature?.algorithm === "ed25519" && vCanon(header, input.signature.signature);
  const att = w.host_identity;
  if (att) {
    const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                    valid_from: att.valid_from, valid_until: att.valid_until,
                    ...("anchors" in att ? { anchors: att.anchors } : {}) };
    if (!(att.host_id === w.host_id && att.public_key === w.public_key
          && vCanon(claim, att.signature))) { console.error("witness attestation INVALID"); ok = false; }
  } else { console.error("chain-witness missing witness attestation"); ok = false; }
  console.log(ok
    ? `VALID (chain-witness: ${w.host_id} countersigned ${input.host_id}@seq ${input.sequence}, head ${String(input.store_head).slice(0, 16)}…)`
    : "INVALID");
} else if (input.kind === "mandate") {
  // Mandate (chp-v0.2.md §10): the principal key signs the canonical header
  // — a bounded, expiring, capability-scoped grant to a named delegate.
  const principal = input.principal ?? {};
  const pPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                        Buffer.from(principal.public_key ?? "", "base64")]),
    format: "der", type: "spki",
  });
  const vCanon = (obj, sigB64) =>
    edVerify(null, Buffer.from(canon(obj), "utf8"), pPub, Buffer.from(sigB64, "base64"));
  const header = { kind: input.kind, mandate_id: input.mandate_id,
                   delegate_id: input.delegate_id, scope: input.scope,
                   valid_from: input.valid_from, valid_until: input.valid_until,
                   created_at: input.created_at, canonicalization: input.canonicalization };
  ok = input.signature?.algorithm === "ed25519" && vCanon(header, input.signature.signature);
  const att = principal.host_identity;
  if (att) {
    const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                    valid_from: att.valid_from, valid_until: att.valid_until,
                    ...("anchors" in att ? { anchors: att.anchors } : {}) };
    if (!(att.host_id === principal.host_id && att.public_key === principal.public_key
          && vCanon(claim, att.signature))) { console.error("principal attestation INVALID"); ok = false; }
  } else { console.error("mandate missing principal attestation"); ok = false; }
  console.log(ok
    ? `VALID (mandate ${input.mandate_id}: ${principal.host_id} → ${input.delegate_id}, scope [${(input.scope ?? []).join(", ")}], until ${input.valid_until})`
    : "INVALID");
} else if (input.kind === "task-bundle") {
  // Task bundle (chp-v0.2.md §8): every member verifies; canonical member order
  // (host_id, root_hash); task_root_hash = SHA256 over member root_hashes + "\n";
  // causal closure — every causation_id resolves inside the union.
  ok = input.bundles.length > 0;
  const keys = input.bundles.map(b => `${b.host_id} ${b.root_hash}`);
  if (!keys.every((k, i) => i === 0 || keys[i - 1] <= k)) { console.error("member order INVALID"); ok = false; }
  const th = createHash("sha256");
  for (const b of input.bundles) th.update((b.root_hash ?? "") + "\n");
  if (th.digest("hex") !== input.task_root_hash) { console.error("task_root_hash mismatch"); ok = false; }
  const allEvents = input.bundles.flatMap(b => b.events);
  const invocations = new Set(allEvents.map(e => e.invocation_id));
  for (const e of allEvents) {
    const c = e.correlation?.causation_id;
    if (c && !invocations.has(c)) { console.error(`dangling causation_id ${c}`); ok = false; }
    if (e.correlation?.correlation_id !== input.correlation_id) { console.error("correlation mismatch"); ok = false; }
  }
  for (const b of input.bundles) { if (!verifyOne(b)) ok = false; }
  // Participation manifest (§8): a declared member set must be fully present.
  const declared = new Set(allEvents
    .filter(e => e.event_type === "task_participants_declared")
    .flatMap(e => e.payload?.participants ?? []));
  if (declared.size > 0) {
    const memberIds = new Set(input.bundles.map(b => b.host_id));
    for (const d of declared) {
      if (!memberIds.has(d)) { console.error(`declared participant ${d} has no bundle`); ok = false; }
    }
  }
  // Aggregator signature (§8 `aggregated`): verified whenever present.
  let aggNote = "";
  if (input.aggregator) {
    const agg = input.aggregator;
    const aggPub = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                          Buffer.from(agg.public_key, "base64")]),
      format: "der", type: "spki",
    });
    const aggVerify = (obj, sigB64) =>
      edVerify(null, Buffer.from(canon(obj), "utf8"), aggPub, Buffer.from(sigB64, "base64"));
    const header = { kind: input.kind, correlation_id: input.correlation_id,
                     protocol_version: input.protocol_version, created_at: input.created_at,
                     canonicalization: input.canonicalization, task_root_hash: input.task_root_hash };
    let aggOk = agg.signature?.algorithm === "ed25519"
      && aggVerify(header, agg.signature.signature);
    const att = agg.host_identity;
    if (att) {
      const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                      valid_from: att.valid_from, valid_until: att.valid_until,
                      ...("anchors" in att ? { anchors: att.anchors } : {}) };
      aggOk = aggOk && att.host_id === agg.host_id && att.public_key === agg.public_key
        && aggVerify(claim, att.signature);
    } else { aggOk = false; }
    if (!aggOk) { console.error("aggregator signature INVALID"); ok = false; }
    else aggNote = `, aggregated by ${agg.host_id}`;
  }
  console.log(ok
    ? `VALID (task-bundle, ${input.bundles.length} hosts, ${allEvents.length} events${aggNote})`
    : "INVALID");
} else {
  ok = verifyOne(input);
  console.log(ok ? `VALID (${input.assurance}, ${input.events.length} events)` : "INVALID");
}
process.exit(ok ? 0 : 1);
