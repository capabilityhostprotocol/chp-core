/**
 * @capabilityhostprotocol/sdk — a pure TypeScript client + verifier for the
 * Capability Host Protocol. No server; Node ≥18, `node:crypto` only.
 *
 * The canonicalization and signing here are byte-compatible with the Python
 * reference and validated against spec/test-vectors/ — this is the second
 * implementation that proves CHP is a protocol, not a Python detail.
 *
 * @packageDocumentation
 */

export {
  canon, encodeStr, canonJcs, encodeStrJcs, canonFor,
  CANONICALIZATION_JCS, type JsonValue,
} from './canon.js';
export { contentHash, rootHash, payloadCommitment, chunkSeqDigest, EVENT_HASH_V2, type EvidenceEvent } from './hash.js';
export { verifyChain, type ChainResult } from './chain.js';
export { orderEvents } from './ordering.js';
export {
  CANONICALIZATION,
  SIGNATURE_ALGORITHM,
  type HostKey,
  keyIdFor,
  publicKeyFromB64,
  keypairFromSeed,
  generateKeypair,
  bundleHeader,
  buildAttestation,
  buildBundle,
  buildCompleteness,
  COMPLETENESS_SCHEME,
  signBundle,
  withholdPayloads,
  buildTaskBundle,
  computeTaskRootHash,
  taskBundleHeader,
  signTaskBundle,
  buildMandate,
  buildSubMandate,
  mandateRootPrincipal,
  attenuates,
  buildMandateRevocation,
  mandateRevocationHeader,
  mandateHeader,
  buildProvenanceStatement,
  provenanceHeader,
  buildContinuityStatement,
  buildChainWitness,
  chainWitnessHeader,
  computeStoreHead,
  computeRevocationHead,
  type StoreHead,
} from './signing.js';
export {
  merkleRoot, inclusionProof, verifyInclusion,
  consistencyProof, verifyConsistency,
  storeHeadRoot, storeHeadInclusionProof, verifyStoreHeadInclusion, storeHeadSchemeMatching,
  storeHeadConsistencyProof, verifyStoreHeadConsistency,
  CHP_STORE_HEAD_V1, CHP_STORE_HEAD_V2,
  type StoreHeadInclusion, type StoreHeadConsistency,
} from './merkle.js';
export {
  bundleToStatement, dsseSign, bundleToAttestation, dsseStatement, attestationToBundle,
  verifyDsse, verifyAttestation,
  IN_TOTO_STATEMENT_TYPE, IN_TOTO_PAYLOAD_TYPE, CHP_BUNDLE_PREDICATE_TYPE,
  type DsseEnvelope, type AttestationVerification,
} from './dsse.js';
export {
  verifyBundle,
  verifyBundleResolved,
  resolveHostIdentity,
  domainAnchor,
  didAnchor,
  didAnchorMessage,
  verifyDidAnchor,
  WELL_KNOWN_IDENTITY_PATH,
  verifyTaskBundle,
  verifyProvenanceStatement,
  verifyMandate,
  verifyMandateRevocation,
  scopeAllows,
  verifyContinuity,
  verifyChainWitness,
  verifyStoreHeadMonitorReport,
  monitorAnchorHistoryRemote,
  type RemoteMonitorVerdict,
  auditCompleteness,
  auditCompletenessViaAnchor,
  type CompletenessAudit,
  verifyStoreHeadAnchor,
  storeHeadAnchorMessage,
  evaluateWitnessQuorum,
  type BundleVerification,
  type TaskBundleVerification,
} from './verify.js';
export {
  parseSshsig,
  verifySshsig,
  didKeyToRaw,
  rawToDidKey,
  DID_ANCHOR_NAMESPACE,
  type ParsedSshsig,
} from './sshsig.js';
export { RemoteCapabilityHost, childCorrelation, type InvocationResult } from './client.js';
export { SUPPORTED_VERSIONS, PROTOCOL_VERSION, versionsUpto, negotiateVersion } from './version.js';
