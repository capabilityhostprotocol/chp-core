/**
 * Content-addressed artifact store — the TS peer of chp_core/artifacts.py (ArtifactStore).
 * Refs in the control plane, bytes in the data plane. `put` is idempotent by construction
 * (same bytes -> same sha256 address); `get` re-verifies the digest so a tampered file raises
 * ArtifactIntegrityError instead of returning wrong bytes. Media type + created_at + optional
 * audience ride a `.meta` sidecar (same bytes keep their address).
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const PREFIX = 'sha256:';

export function artifactIdFor(data: Buffer): string {
  return PREFIX + createHash('sha256').update(data).digest('hex');
}

export class ArtifactIntegrityError extends Error {}
export class ArtifactNotFoundError extends Error {}
export class ArtifactIdInvalidError extends Error {}

export interface ArtifactRef {
  artifact_id: string;
  media_type: string;
  size_bytes: number;
  created_at: string;
}

interface Meta {
  media_type: string;
  created_at: string;
  audience?: string[];
}

export class ArtifactStore {
  readonly root: string;
  constructor(root: string) {
    this.root = root;
    mkdirSync(root, { recursive: true });
  }

  // digest path — validates the id shape (ValueError parity → ArtifactIdInvalidError)
  private pathFor(artifactId: string): string {
    if (!artifactId.startsWith(PREFIX)) throw new ArtifactIdInvalidError(`not an artifact id: ${artifactId}`);
    const digest = artifactId.slice(PREFIX.length);
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new ArtifactIdInvalidError(`malformed artifact digest: ${artifactId}`);
    return join(this.root, digest);
  }

  private readMeta(path: string): Meta {
    const metaPath = `${path}.meta`;
    if (!existsSync(metaPath)) return { media_type: 'application/octet-stream', created_at: '' };
    return JSON.parse(readFileSync(metaPath, 'utf8')) as Meta;
  }

  put(data: Buffer, mediaType = 'application/octet-stream', audience?: string[]): ArtifactRef {
    const ref: ArtifactRef = {
      artifact_id: artifactIdFor(data),
      media_type: mediaType,
      size_bytes: data.length,
      created_at: new Date().toISOString(),
    };
    const path = this.pathFor(ref.artifact_id);
    if (!existsSync(path)) {
      writeFileSync(path, data);
      const meta: Meta = { media_type: mediaType, created_at: ref.created_at };
      if (audience && audience.length) meta.audience = [...audience];
      writeFileSync(`${path}.meta`, JSON.stringify(meta));
    }
    return ref;
  }

  // The artifact's audience allowlist, or null when unbounded. Existence precedes access:
  // an unknown id throws ArtifactNotFoundError (checked BEFORE the bytes are served).
  accessOf(artifactId: string): string[] | null {
    const path = this.pathFor(artifactId);
    if (!existsSync(path)) throw new ArtifactNotFoundError(artifactId);
    return this.readMeta(path).audience ?? null;
  }

  get(artifactId: string): { data: Buffer; mediaType: string } {
    const path = this.pathFor(artifactId);
    if (!existsSync(path)) throw new ArtifactNotFoundError(artifactId);
    const data = readFileSync(path);
    // Integrity is a REFUSAL, never wrong bytes (artifact-substitution case).
    if (artifactIdFor(data) !== artifactId) {
      throw new ArtifactIntegrityError(`stored bytes no longer match ${artifactId}`);
    }
    return { data, mediaType: this.readMeta(path).media_type };
  }
}
