import { pathToFileURL } from 'node:url';

import {
  reviewActivationRuntimeReadbackConfiguration,
  validateReviewActivationRuntimeEnvelope,
} from '../netlify/lib/review-activation-runtime-readback-core.mjs';

const CANDIDATE_ENV = 'ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_CANDIDATE_JSON';

export function createReviewActivationRuntimeReadbackPreflightReport(
  env = process.env,
  { mode = 'off', now = new Date(), deploymentSha } = {},
) {
  if (!['off', 'production'].includes(mode) || !(now instanceof Date) ||
      !Number.isFinite(now.getTime())) {
    throw new TypeError('Runtime readback preflight options are invalid.');
  }
  const requested = env.ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED === 'true';
  if (mode === 'off') {
    return Object.freeze({
      schema: 'arc-review-activation-runtime-readback-preflight-v1',
      mode,
      state: requested ? 'INVALID' : 'SAFE_OFF',
      ok: !requested,
      checks: Object.freeze({ configured: false, current_signed_candidate: false }),
      invalid: Object.freeze(requested ? ['ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED'] : []),
      missing: Object.freeze([]),
    });
  }
  const configuration = reviewActivationRuntimeReadbackConfiguration(env, now, { deploymentSha });
  const missing = [];
  const invalid = [];
  for (const name of [
    'ARC_REVIEW_ACTIVATION_RUNTIME_READBACK_ENABLED',
    'ARC_REVIEW_ACTIVATION_VERIFIER_ED25519_PUBLIC_KEY',
    'ARC_REVIEW_ACTIVATION_VERIFIER_URL',
    CANDIDATE_ENV,
  ]) {
    if (env[name] === undefined || env[name] === '') missing.push(name);
  }
  if (requested && !configuration.enabled) invalid.push('RUNTIME_READBACK_AUTHORITY_CONFIGURATION');
  let candidate = null;
  if (env[CANDIDATE_ENV]) {
    try { candidate = JSON.parse(env[CANDIDATE_ENV]); } catch {
      invalid.push(`${CANDIDATE_ENV}:JSON`);
    }
  }
  const candidateCurrent = candidate !== null && validateReviewActivationRuntimeEnvelope(
    env,
    candidate,
    now,
    { deploymentSha },
  );
  if (candidate !== null && !candidateCurrent) invalid.push(`${CANDIDATE_ENV}:INVALID`);
  const uniqueMissing = [...new Set(missing)].sort();
  const uniqueInvalid = [...new Set(invalid)].sort();
  const ok = configuration.enabled && candidateCurrent &&
    uniqueMissing.length === 0 && uniqueInvalid.length === 0;
  return Object.freeze({
    schema: 'arc-review-activation-runtime-readback-preflight-v1',
    mode,
    state: ok ? 'PRODUCTION_CURRENT' : 'PRODUCTION_BLOCKED',
    ok,
    checks: Object.freeze({
      configured: configuration.enabled,
      current_signed_candidate: candidateCurrent,
      deployment_bound: configuration.deployment_sha !== null,
      manifest_authority_bound: configuration.manifest_bound,
    }),
    invalid: Object.freeze(uniqueInvalid),
    missing: Object.freeze(uniqueMissing),
  });
}

export function runReviewActivationRuntimeReadbackPreflightCli({
  argv = process.argv.slice(2),
  env = process.env,
  now = new Date(),
  deploymentSha,
  write = (value) => process.stdout.write(value),
} = {}) {
  const matches = argv.map((arg) => /^--mode=(off|production)$/.exec(arg)).filter(Boolean);
  if (matches.length !== 1 || argv.length !== 1) return 2;
  const report = createReviewActivationRuntimeReadbackPreflightReport(env, {
    mode: matches[0][1],
    now,
    deploymentSha,
  });
  write(`${JSON.stringify(report)}\n`);
  return report.ok ? 0 : 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = runReviewActivationRuntimeReadbackPreflightCli();
}
