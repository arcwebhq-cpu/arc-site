import { createHash } from 'node:crypto';

import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_VERSION,
  signActivationManifest,
} from '../../netlify/lib/activation-manifest-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function testActivationAuthority(now, {
  stage = 'PUBLIC_INTAKE',
  issuedAt = new Date(new Date(now).getTime() - 60_000),
  expiresAt = new Date(new Date(now).getTime() + 60 * 60_000),
  deploymentSha = '9'.repeat(40),
  secret = 'test-only-activation-manifest-secret-0123456789abcdef',
} = {}) {
  const unsigned = {
    schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage,
  authority_mode: 'ROLLOUT',
    issued_at: new Date(issuedAt).toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    deployment_sha: deploymentSha,
    evidence: ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
      kind,
      receipt_ref: `audit:${sha256(`receipt:${kind}`).slice(0, 24)}`,
      sha256: sha256(`evidence:${kind}`),
    })),
  };
  return {
    ARC_ACTIVATION_MANIFEST_HMAC_SECRET: secret,
    ARC_ACTIVATION_MANIFEST: signActivationManifest(unsigned, secret),
    COMMIT_REF: deploymentSha,
  };
}
