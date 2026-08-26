import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  ACTIVATION_EVIDENCE_BY_STAGE,
  ACTIVATION_MANIFEST_ENV,
  ACTIVATION_MANIFEST_MAX_LIFETIME_MS,
  ACTIVATION_MANIFEST_SCHEMA,
  ACTIVATION_MANIFEST_SECRET_ENV,
  ACTIVATION_MANIFEST_STEADY_MAX_LIFETIME_MS,
  ACTIVATION_NEXT_MANIFEST_ENV,
  ACTIVATION_STEADY_EVIDENCE_KINDS,
  ACTIVATION_MANIFEST_VERSION,
  ACTIVATION_STAGES,
  activationManifestSecretIsDistinct,
  activationStageAtLeast,
  signActivationManifest,
  validateActivationManifest,
  validateActivationManifestEnvironment,
} from '../netlify/lib/activation-manifest-core.mjs';

const now = new Date('2026-08-26T18:00:00.000Z');
const deploymentSha = '9'.repeat(40);
const secret = 'activation-manifest-only-hmac-secret-0123456789abcdef';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const evidenceFor = (stage) => ACTIVATION_EVIDENCE_BY_STAGE[stage].map((kind) => ({
  kind,
  receipt_ref: `audit:${sha256(`receipt:${kind}`).slice(0, 24)}`,
  sha256: sha256(`evidence:${kind}`),
}));
const unsigned = (stage, overrides = {}) => ({
  schema: ACTIVATION_MANIFEST_SCHEMA,
  version: ACTIVATION_MANIFEST_VERSION,
  stage,
  authority_mode: 'ROLLOUT',
  issued_at: new Date(now.getTime() - 60_000).toISOString(),
  expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
  deployment_sha: deploymentSha,
  evidence: evidenceFor(stage),
  ...overrides,
});
const signed = (stage, overrides = {}) => signActivationManifest(unsigned(stage, overrides), secret);

const steadyEvidenceFor = (stage) => [...evidenceFor(stage), ...ACTIVATION_STEADY_EVIDENCE_KINDS.map((kind) => ({
  kind,
  receipt_ref: `audit:${sha256(`receipt:${kind}`).slice(0, 24)}`,
  sha256: sha256(`evidence:${kind}`),
}))];

assert.deepEqual(ACTIVATION_STAGES, [
  'OFF', 'EMAIL_SANDBOX', 'CLAIM_SANDBOX', 'LIVE_CHECKOUT', 'PUBLIC_INTAKE', 'PILOT', 'OUTREACH',
]);
for (const [stageIndex, stage] of ACTIVATION_STAGES.entries()) {
  for (const [minimumIndex, minimumStage] of ACTIVATION_STAGES.entries()) {
    assert.equal(activationStageAtLeast(stage, minimumStage), stageIndex >= minimumIndex);
  }
}
assert.equal(activationStageAtLeast('UNKNOWN', 'OFF'), false);

for (const stage of ACTIVATION_STAGES) {
  const validated = validateActivationManifest(signed(stage), {
    secret, deploymentSha, minimumStage: stage, now,
  });
  assert.equal(validated.valid, true, `${stage} should validate at its own ordered gate.`);
  assert.equal(validated.stage, stage);
  assert.deepEqual(validated.reason_codes, []);
  assert.deepEqual(validated.checks, {
    canonical: true,
    signature_valid: true,
    current: true,
    deployment_bound: true,
    evidence_complete: true,
    stage_sufficient: true,
  });
}

const publicIntake = signed('PUBLIC_INTAKE');
const badSignature = JSON.parse(publicIntake);
badSignature.signature = `${badSignature.signature.slice(0, -1)}${badSignature.signature.endsWith('0') ? '1' : '0'}`;
assert.equal(validateActivationManifest(publicIntake, {
  secret, deploymentSha, minimumStage: 'LIVE_CHECKOUT', now,
}).valid, true);
assert.deepEqual(validateActivationManifest(publicIntake, {
  secret, deploymentSha, minimumStage: 'PILOT', now,
}).reason_codes, ['STAGE_INSUFFICIENT']);
assert.deepEqual(validateActivationManifest('', {
  secret, deploymentSha, minimumStage: 'OFF', now,
}).reason_codes, ['MANIFEST_MISSING']);

const cases = [
  [JSON.stringify(badSignature), 'SIGNATURE_INVALID'],
  [` ${publicIntake}`, 'MANIFEST_NOT_CANONICAL'],
  [signed('PUBLIC_INTAKE', { deployment_sha: 'b'.repeat(40) }), 'DEPLOYMENT_SHA_MISMATCH'],
  [signed('PUBLIC_INTAKE', {
    issued_at: new Date(now.getTime() - 2 * 60 * 60_000).toISOString(),
    expires_at: new Date(now.getTime() - 1).toISOString(),
  }), 'MANIFEST_NOT_CURRENT'],
  [signed('PUBLIC_INTAKE', {
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ACTIVATION_MANIFEST_MAX_LIFETIME_MS + 1).toISOString(),
  }), 'MANIFEST_NOT_CURRENT'],
  [signed('PUBLIC_INTAKE', {
    issued_at: new Date(now.getTime() + 60_001).toISOString(),
    expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
  }), 'MANIFEST_NOT_CURRENT'],
  [signActivationManifest(unsigned('PUBLIC_INTAKE', { evidence: evidenceFor('LIVE_CHECKOUT') }), secret), 'EVIDENCE_INCOMPLETE'],
];
for (const [raw, reason] of cases) {
  const validated = validateActivationManifest(raw, { secret, deploymentSha, minimumStage: 'PUBLIC_INTAKE', now });
  assert.equal(validated.valid, false);
  assert.deepEqual(validated.reason_codes, [reason]);
}

const steadyPilot = signed('PILOT', {
  authority_mode: 'STEADY_STATE',
  expires_at: new Date(now.getTime() + ACTIVATION_MANIFEST_STEADY_MAX_LIFETIME_MS - 60_000).toISOString(),
  evidence: steadyEvidenceFor('PILOT'),
});
const steadyValidated = validateActivationManifest(steadyPilot, {
  secret, deploymentSha, minimumStage: 'PILOT', now,
});
assert.equal(steadyValidated.valid, true);
assert.equal(steadyValidated.authority_mode, 'STEADY_STATE');
assert.equal(steadyValidated.rotation_due, false);
const steadyRotationDue = validateActivationManifest(signed('PILOT', {
  authority_mode: 'STEADY_STATE',
  expires_at: new Date(now.getTime() + 6 * 24 * 60 * 60_000).toISOString(),
  evidence: steadyEvidenceFor('PILOT'),
}), { secret, deploymentSha, minimumStage: 'PILOT', now });
assert.equal(steadyRotationDue.valid, true);
assert.equal(steadyRotationDue.rotation_due, true);
assert.deepEqual(validateActivationManifest(signed('PUBLIC_INTAKE', {
  authority_mode: 'STEADY_STATE',
  evidence: [...evidenceFor('PUBLIC_INTAKE'), ...ACTIVATION_STEADY_EVIDENCE_KINDS.map((kind) => ({
    kind, receipt_ref: `audit:${sha256(kind).slice(0, 24)}`, sha256: sha256(kind),
  }))],
}), { secret, deploymentSha, minimumStage: 'PUBLIC_INTAKE', now }).reason_codes,
['STEADY_STATE_STAGE_INVALID']);

const malformedEvidence = JSON.parse(publicIntake);
malformedEvidence.evidence[0] = null;
assert.doesNotThrow(() => validateActivationManifest(JSON.stringify(malformedEvidence), {
  secret, deploymentSha, minimumStage: 'PUBLIC_INTAKE', now,
}));
assert.deepEqual(validateActivationManifest(JSON.stringify(malformedEvidence), {
  secret, deploymentSha, minimumStage: 'PUBLIC_INTAKE', now,
}).reason_codes, ['EVIDENCE_SHAPE_INVALID']);

const unknownKey = JSON.parse(publicIntake);
unknownKey.unexpected = true;
assert.deepEqual(validateActivationManifest(JSON.stringify(unknownKey), {
  secret, deploymentSha, minimumStage: 'PUBLIC_INTAKE', now,
}).reason_codes, ['MANIFEST_SHAPE_INVALID']);
assert.throws(() => signActivationManifest(unsigned('OFF'), 'too-short'), /secret is invalid/i);

const env = {
  [ACTIVATION_MANIFEST_ENV]: publicIntake,
  [ACTIVATION_MANIFEST_SECRET_ENV]: secret,
  ARC_OTHER_SIGNING_SECRET: 'other-dedicated-signing-secret-0123456789abcdef',
  COMMIT_REF: '8'.repeat(40),
};
assert.equal(activationManifestSecretIsDistinct(env), true);
assert.equal(validateActivationManifestEnvironment(env, { minimumStage: 'PUBLIC_INTAKE', now }).valid, true);
assert.equal(validateActivationManifestEnvironment({ ...env, COMMIT_REF: 'not-a-sha' }, {
  minimumStage: 'PUBLIC_INTAKE', now,
}).valid, true, 'runtime COMMIT_REF must not influence the embedded build identity');
assert.equal(validateActivationManifestEnvironment({
  ...env,
  [ACTIVATION_MANIFEST_ENV]: signed('PUBLIC_INTAKE', { deployment_sha: '8'.repeat(40) }),
  [ACTIVATION_NEXT_MANIFEST_ENV]: publicIntake,
}, { minimumStage: 'PUBLIC_INTAKE', now }).valid, true,
'a reviewed overlapping next slot may carry authority for the embedded deployment SHA');
const reusedSecretEnv = { ...env, ARC_OTHER_SIGNING_SECRET: secret };
assert.equal(activationManifestSecretIsDistinct(reusedSecretEnv), false);
assert.deepEqual(validateActivationManifestEnvironment(reusedSecretEnv, {
  minimumStage: 'PUBLIC_INTAKE', now,
}).reason_codes, ['SECRET_NOT_DISTINCT']);
for (const name of ['NETLIFY_ACCESS_TOKEN', 'ARC_PROVIDER_PASSWORD', 'ARC_PROVIDER_CREDENTIALS']) {
  assert.equal(activationManifestSecretIsDistinct({ ...env, [name]: secret }), false,
    `${name} must not reuse the activation HMAC secret.`);
}

const serializedResult = JSON.stringify(validateActivationManifestEnvironment(env, {
  minimumStage: 'PUBLIC_INTAKE', now,
}));
assert.equal(serializedResult.includes(secret), false);
assert.equal(serializedResult.includes(deploymentSha), false);
assert.equal(serializedResult.includes('receipt:'), false);
assert.equal(serializedResult.includes('audit:'), false);

console.log('ARC signed ordered activation manifest contract passed.');
