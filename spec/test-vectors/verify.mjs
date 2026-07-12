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

// chp-jcs-v1 (RFC 8785 JCS, proposal 0015): compact separators (,/:), raw UTF-8
// strings (no \uXXXX escaping — only " \ and control chars escape), keys sorted
// by UTF-16 code unit (JS .sort() default — matches Python's utf-16-be sort).
// Over CHP's float-free content the RFC 8785 number algorithm is never exercised
// (§2 rule 6 retained: non-integers throw). Governs the bundle HEADER signature;
// the host_identity attestation stays chp-stable-v1.
function canonJcs(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("chp-jcs-v1 forbids non-integer numbers (§2 rule 6)");
    return String(v);
  }
  if (typeof v === "string") return encodeStrJcs(v);
  if (Array.isArray(v)) return "[" + v.map(canonJcs).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => encodeStrJcs(k) + ":" + canonJcs(v[k])).join(",") + "}";
}
function encodeStrJcs(s) {
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
    else out += ch;   // raw UTF-8 (incl. non-ASCII and astral)
  }
  return out + '"';
}

// The canonicalization dispatch seam (§2): pick the header serializer by the
// bundle's `canonicalization`. Absent/legacy → chp-stable-v1; unknown throws.
function canonFor(scheme) {
  if (scheme === "chp-jcs-v1") return canonJcs;
  if (scheme == null || scheme === "" || scheme === "chp-stable-v1") return canon;
  throw new Error(`unknown canonicalization scheme: ${scheme}`);
}
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// RFC 6962 Merkle verify for chp-store-head-v2 inclusion (§12, proposal 0019).
// Domain-separated: leaf SHA256(0x00‖data), node SHA256(0x01‖L‖R). Recomputes by
// replaying the split (largest power of two < size) — the inverse of the build.
const _leafHash = (data) => createHash("sha256").update(Buffer.concat([Buffer.from([0]), data])).digest();
const _nodeHash = (l, r) => createHash("sha256").update(Buffer.concat([Buffer.from([1]), l, r])).digest();
function _splitN(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function _walk(size, index, path, leaf) {
  if (size === 1) return leaf;
  const k = _splitN(size);
  // The recursion consumes deeper path entries FIRST; the sibling is shifted
  // AFTER (bind it explicitly — do not rely on argument evaluation order).
  if (index < k) {
    const left = _walk(k, index, path, leaf);
    return _nodeHash(left, path.shift());          // sibling on the right
  }
  const right = _walk(size - k, index - k, path, leaf);
  return _nodeHash(path.shift(), right);           // sibling on the left
}
function verifyStoreHeadInclusion(rootHex, correlationId, headHash, proof) {
  if (proof.scheme !== "chp-store-head-v2" || proof.correlation_id !== correlationId
      || proof.head_hash !== headHash) return false;
  if (!(proof.leaf_index >= 0 && proof.leaf_index < proof.tree_size)) return false;
  const leafBytes = Buffer.from(`${correlationId}\x00${headHash ?? ""}\n`, "utf8");
  const path = (proof.audit_path ?? []).map((h) => Buffer.from(h, "hex"));
  const computed = _walk(proof.tree_size, proof.leaf_index, path, _leafHash(leafBytes));
  return path.length === 0 && computed.toString("hex") === rootHex;
}

// RFC 6962 §2.1.2 consistency verify (§12, proposal 0022). Replay SUBPROOF(m, n, b):
// recompute BOTH the old root (size m) and new root (size n); bind each shifted
// entry AFTER the recursion (no argument-evaluation-order reliance, as in _walk).
function _consistencyWalk(m, n, b, path, firstRoot) {
  if (m === n) {
    if (b) return [firstRoot, firstRoot];       // verifier-known root, omitted
    const h = path.shift();
    return [h, h];
  }
  const k = _splitN(n);
  if (m <= k) {
    const [old, newLeft] = _consistencyWalk(m, k, b, path, firstRoot);
    const right = path.shift();                  // new right subtree
    return [old, _nodeHash(newLeft, right)];
  }
  const [oldRight, newRight] = _consistencyWalk(m - k, n - k, false, path, firstRoot);
  const left = path.shift();                     // shared left subtree
  return [_nodeHash(left, oldRight), _nodeHash(left, newRight)];
}
function verifyConsistency(firstRootHex, secondRootHex, m, n, proofHex) {
  if (!(m >= 0 && m <= n)) return false;
  if (m === 0) return proofHex.length === 0;
  if (m === n) return proofHex.length === 0 && firstRootHex === secondRootHex;
  const path = proofHex.map((h) => Buffer.from(h, "hex"));
  const first = Buffer.from(firstRootHex, "hex");
  const [old, next] = _consistencyWalk(m, n, true, path, first);
  return path.length === 0
    && old.toString("hex") === firstRootHex && next.toString("hex") === secondRootHex;
}

// chp-event-hash-v2 (14): sha256(chp-stable-v1(payload)). Empty payload = {}.
const payloadCommitment = (payload) => sha256hex(canon(payload ?? {}));

function contentHash(ev, prevHash) {
  const corr = ev.correlation || {};
  const stable = {
    event_id: ev.event_id, event_type: ev.event_type, invocation_id: ev.invocation_id,
    capability_id: ev.capability_id, host_id: ev.host_id,
    correlation_id: typeof corr === "object" ? (corr.correlation_id ?? null) : null,
    timestamp: ev.timestamp, outcome: ev.outcome ?? null,
    prev_hash: prevHash ?? null,
  };
  // Per-event hash scheme (2/14): v2 commits to payload_commitment in place of
  // the inline payload, so the payload may be withheld. Absent scheme = v1.
  if (ev.hash_scheme === "chp-event-hash-v2") {
    stable.payload_commitment = ev.payload_commitment ?? payloadCommitment(ev.payload);
  } else {
    stable.payload = ev.payload ?? {};
  }
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
  // v2 (14): a DISCLOSED payload must match the signed commitment; a WITHHELD
  // one ({chp_withheld:true}) is skipped — the commitment alone secures the chain.
  if (ev.hash_scheme === "chp-event-hash-v2"
      && !(ev.payload && ev.payload.chp_withheld === true)
      && payloadCommitment(ev.payload) !== ev.payload_commitment) {
    console.error(`payload_commitment mismatch on ${ev.event_id}`); ok = false;
  }
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
  // bare root_hash — so a relabelled host_id breaks it. The header serializer
  // dispatches on `canonicalization` (§2 seam); an unknown scheme fails, never
  // crashes. The attestation below stays chp-stable-v1 (signed at keygen time).
  let headerCanon;
  try { headerCanon = canonFor(bundle.canonicalization); }
  catch (e) { console.error(e.message); return false; }
  // completeness (§12, proposal 0018) rides INSIDE the signed header, omit-when-
  // absent — so a pre-0018 bundle's header is byte-identical.
  const header = { host_id: bundle.host_id, protocol_version: bundle.protocol_version,
                   created_at: bundle.created_at, canonicalization: bundle.canonicalization,
                   root_hash: bundle.root_hash,
                   ...(bundle.completeness ? { completeness: bundle.completeness } : {}) };
  const headerSigOk = edVerify(null, Buffer.from(headerCanon(header), "utf8"),
                               pub, Buffer.from(bundle.signature.signature, "base64"));
  if (!headerSigOk) { console.error("signature INVALID"); ok = false; }

  // Completeness self-check: the claim's head_hash MUST be the tail event's
  // content_hash (with genesis-contiguity above, this is a full genesis→tail
  // chain as claimed). The teeth — auditing vs a witnessed head — is a separate
  // witness-side act (chp completeness verify); here we check self-consistency.
  if (bundle.completeness) {
    const c = bundle.completeness;
    const tail = bundle.events[bundle.events.length - 1] || {};
    const tailCorr = (tail.correlation || {}).correlation_id;
    const selfOk = c.scheme === "chp-completeness-v1"
      && c.head_hash === tail.content_hash
      && (tailCorr == null || c.correlation_id === tailCorr);
    if (!selfOk) { console.error("completeness self-check INVALID"); ok = false; }
  }

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
  // revocation_head (proposal 0010) is header-signed ONLY when present — a
  // pre-0010 statement omits it and the header is byte-identical.
  const header = { kind: input.kind, host_id: input.host_id, sequence: input.sequence,
                   store_head: input.store_head, witnessed_at: input.witnessed_at,
                   canonicalization: input.canonicalization,
                   ...(input.revocation_head ? { revocation_head: input.revocation_head } : {}) };
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
    ? `VALID (chain-witness: ${w.host_id} countersigned ${input.host_id}@seq ${input.sequence}, head ${String(input.store_head).slice(0, 16)}…`
      + `${input.revocation_head ? `, revocation_head ${String(input.revocation_head).slice(0, 16)}…` : ""})`
    : "INVALID");
} else if (input.kind === "witness-quorum") {
  // chp-witness-quorum-v1 (§12, proposal 0013): verify EACH chain-witness over
  // the same head independently, dedupe by signature.key_id, count vs k.
  const distinct = new Set();
  for (const s of input.statements) {
    if (s.host_id !== input.host_id || s.sequence !== input.sequence
        || s.store_head !== input.store_head) continue;
    const w = s.witness ?? {};
    const wPub = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                          Buffer.from(w.public_key ?? "", "base64")]),
      format: "der", type: "spki" });
    const header = { kind: s.kind, host_id: s.host_id, sequence: s.sequence,
                     store_head: s.store_head, witnessed_at: s.witnessed_at,
                     canonicalization: s.canonicalization,
                     ...(s.revocation_head ? { revocation_head: s.revocation_head } : {}) };
    const sigOk = s.signature?.algorithm === "ed25519"
      && edVerify(null, Buffer.from(canon(header), "utf8"), wPub, Buffer.from(s.signature.signature, "base64"));
    if (sigOk && s.signature?.key_id) distinct.add(s.signature.key_id);
  }
  ok = distinct.size >= input.k && input.expected_verdict === "quorum_met"
    && distinct.size === input.expected_distinct;
  console.log(ok ? `VALID (witness-quorum: ${distinct.size}/${input.k} distinct witnesses → quorum_met)`
                 : `INVALID (quorum: ${distinct.size} distinct, expected ${input.expected_distinct})`);
} else if (input.kind === "chunk-seq") {
  // chp-chunk-seq-v1 (§13.1): SHA-256 over each chp-stable-v1(delta) + "\n", in order.
  const h = createHash("sha256");
  for (const d of input.deltas) h.update(canon(d) + "\n");
  const digest = h.digest("hex");
  ok = digest === input.chunk_seq_digest;
  console.log(ok ? `VALID (chunk-seq: ${input.deltas.length} deltas → ${digest.slice(0, 16)}…)`
                 : "INVALID (chunk-seq digest mismatch)");
} else if (input.kind === "mandate") {
  // Mandate (chp-v0.2.md §10) + sub-delegation chains (§10, proposal 0009):
  // the principal key signs the canonical header (a sub-mandate's header also
  // covers depth+parent_id — present only when parent_id is set, so a root is
  // byte-identical); each link must ATTENUATE its embedded parent, recursively.
  const scopeAllows = (scope, cap) => (scope ?? []).some(
    (s) => cap === s || (String(s).endsWith("*") && cap.startsWith(String(s).slice(0, -1))));
  const verifyLink = (m) => {
    const principal = m.principal ?? {};
    const pPub = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                          Buffer.from(principal.public_key ?? "", "base64")]),
      format: "der", type: "spki",
    });
    const vC = (obj, sigB64) =>
      edVerify(null, Buffer.from(canon(obj), "utf8"), pPub, Buffer.from(sigB64, "base64"));
    const header = { kind: m.kind, mandate_id: m.mandate_id,
                     delegate_id: m.delegate_id, scope: m.scope,
                     valid_from: m.valid_from, valid_until: m.valid_until,
                     created_at: m.created_at, canonicalization: m.canonicalization,
                     ...(m.parent_id ? { depth: m.depth, parent_id: m.parent_id } : {}) };
    let good = m.signature?.algorithm === "ed25519" && vC(header, m.signature.signature);
    const att = principal.host_identity;
    if (att) {
      const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                      valid_from: att.valid_from, valid_until: att.valid_until,
                      ...("anchors" in att ? { anchors: att.anchors } : {}) };
      if (!(att.host_id === principal.host_id && att.public_key === principal.public_key
            && vC(claim, att.signature))) { console.error("principal attestation INVALID"); good = false; }
    } else { console.error("mandate missing principal attestation"); good = false; }
    if (m.parent) {
      const p = m.parent;
      const attenuates = (m.scope ?? []).length > 0
        && (m.scope ?? []).every((s) => scopeAllows(p.scope, s))
        && String(p.valid_from ?? "") <= String(m.valid_from ?? "")
        && String(m.valid_until ?? "") <= String(p.valid_until ?? "")
        && p.delegate_id === principal.host_id
        && m.parent_id === p.mandate_id
        && m.depth === ((p.depth ?? 0) + 1);
      if (!attenuates) { console.error("sub-mandate does not attenuate its parent"); good = false; }
      if (!verifyLink(p)) good = false;
    }
    return good;
  };
  ok = verifyLink(input);
  console.log(ok
    ? `VALID (mandate ${input.mandate_id}: ${(input.principal ?? {}).host_id} → ${input.delegate_id}`
      + `${input.parent_id ? ` — sub of ${input.parent_id} at depth ${input.depth}` : ""})`
    : "INVALID");
} else if (input.kind === "mandate-revocation") {
  // Mandate revocation (chp-v0.2.md §10, proposal 0007): the principal key
  // signs the canonical header — the issuer's withdrawal of a mandate.
  // Whether it revokes a GIVEN mandate is the issuer-only key match a
  // verifier performs against that mandate's principal key.
  const principal = input.principal ?? {};
  const pPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                        Buffer.from(principal.public_key ?? "", "base64")]),
    format: "der", type: "spki",
  });
  const vCanon = (obj, sigB64) =>
    edVerify(null, Buffer.from(canon(obj), "utf8"), pPub, Buffer.from(sigB64, "base64"));
  const header = { kind: input.kind, mandate_id: input.mandate_id,
                   revoked_at: input.revoked_at, reason: input.reason,
                   canonicalization: input.canonicalization };
  ok = input.signature?.algorithm === "ed25519" && vCanon(header, input.signature.signature);
  const att = principal.host_identity;
  if (att) {
    const claim = { host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
                    valid_from: att.valid_from, valid_until: att.valid_until,
                    ...("anchors" in att ? { anchors: att.anchors } : {}) };
    if (!(att.host_id === principal.host_id && att.public_key === principal.public_key
          && vCanon(claim, att.signature))) { console.error("principal attestation INVALID"); ok = false; }
  } else { console.error("mandate-revocation missing principal attestation"); ok = false; }
  console.log(ok
    ? `VALID (mandate-revocation: ${principal.host_id} revoked ${input.mandate_id} at ${input.revoked_at})`
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
} else if (input.kind === "store-head-inclusion") {
  // Third-party non-omission (chp-v0.2.md §12, proposal 0019): recompute the RFC
  // 6962 Merkle root from one correlation's leaf up the audit path and check it
  // equals the anchored root — no leaves, no witness. (The anchor's external
  // SSHSIG is verified by the Python/TS impls; this stdlib check proves the tree.)
  const { anchor, proof } = input;
  const root = anchor?.store_head;
  ok = anchor?.store_head_scheme === "chp-store-head-v2"
    && verifyStoreHeadInclusion(root, proof.correlation_id, proof.head_hash, proof);
  // a forged tail must fail
  const forgeFails = !verifyStoreHeadInclusion(root, proof.correlation_id, "f".repeat(64), proof);
  ok = ok && forgeFails;
  console.log(ok
    ? `VALID (store-head-inclusion: ${proof.correlation_id} committed under anchored Merkle root ${String(root).slice(0, 16)}…)`
    : "INVALID");
} else if (input.kind === "store-head-consistency") {
  // Append-only across two anchored heads (chp-v0.2.md §12, proposal 0022):
  // the two roots in the proof must equal the anchored store_heads, then
  // recompute BOTH from the RFC 6962 §2.1.2 proof — no leaves, no witness.
  const { first_anchor, second_anchor, proof } = input;
  const oldRoot = first_anchor?.store_head, newRoot = second_anchor?.store_head;
  ok = first_anchor?.store_head_scheme === "chp-store-head-v2"
    && second_anchor?.store_head_scheme === "chp-store-head-v2"
    && proof.first_root === oldRoot && proof.second_root === newRoot
    && verifyConsistency(oldRoot, newRoot, proof.first_size, proof.second_size, proof.proof);
  // a later head that dropped a leaf (fewer leaves → different root) must fail
  const truncFails = !verifyConsistency(oldRoot, "0".repeat(64),
                                        proof.first_size, proof.second_size, proof.proof);
  ok = ok && truncFails;
  console.log(ok
    ? `VALID (store-head-consistency: log append-only ${oldRoot.slice(0, 12)}…→${newRoot.slice(0, 12)}…, ${proof.first_size}→${proof.second_size} leaves)`
    : "INVALID");
} else if (input.kind === "dsse" || input.payloadType === "application/vnd.in-toto+json") {
  // in-toto / DSSE attestation (chp-v0.2.md §15, proposal 0021). Level 1: any
  // DSSE verifier recomputes the PAE = "DSSEv1 SP LEN(type) SP type SP LEN(body)
  // SP body" (body = the raw base64-decoded payload) and checks ed25519(PAE).
  // Level 2: the embedded CHP bundle (the predicate) verifies + subject digest.
  const body = Buffer.from(input.payload, "base64");
  const pt = Buffer.from(String(input.payloadType), "utf8");
  const pae = Buffer.concat([
    Buffer.from("DSSEv1 "), Buffer.from(String(pt.length)), Buffer.from(" "), pt,
    Buffer.from(" "), Buffer.from(String(body.length)), Buffer.from(" "), body]);
  const stmt = JSON.parse(body.toString("utf8"));
  const bundle = stmt.predicate ?? {};
  const raw = Buffer.from(bundle.public_key ?? "", "base64");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const pub = createPublicKey({ key: spki, format: "der", type: "spki" });
  const sigOk = (input.signatures ?? []).some((s) =>
    edVerify(null, pae, pub, Buffer.from(s.sig ?? "", "base64")));
  const subjOk = stmt.subject?.[0]?.digest?.sha256 === bundle.root_hash;
  const bundleOk = verifyOne(bundle);
  ok = sigOk && subjOk && bundleOk
    && stmt._type === "https://in-toto.io/Statement/v1"
    && stmt.predicateType === "https://chp.dev/attestation/evidence-bundle/v1";
  if (!sigOk) console.error("DSSE PAE signature INVALID");
  if (!subjOk) console.error("subject digest ≠ bundle root_hash");
  console.log(ok
    ? `VALID (dsse in-toto attestation: ${stmt.subject?.[0]?.name} → bundle ${String(bundle.root_hash).slice(0, 16)}…)`
    : "INVALID");
} else {
  ok = verifyOne(input);
  console.log(ok ? `VALID (${input.assurance}, ${input.events.length} events)` : "INVALID");
}
process.exit(ok ? 0 : 1);
