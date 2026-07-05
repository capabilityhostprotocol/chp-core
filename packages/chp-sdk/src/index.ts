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

export { canon, encodeStr, type JsonValue } from './canon.js';
export { contentHash, rootHash, type EvidenceEvent } from './hash.js';
export { verifyChain, type ChainResult } from './chain.js';
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
  signBundle,
} from './signing.js';
export { verifyBundle, type BundleVerification } from './verify.js';
export { RemoteCapabilityHost, type InvocationResult } from './client.js';
