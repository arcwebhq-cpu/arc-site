import { INTAKE_BUILD_MARKER } from '../lib/intake-build-marker.mjs';
import {
  INTAKE_READINESS_ENV,
  intakeActivationReady,
  intakeArc1RuntimeReady,
  intakeEnabledFromAttestation,
  intakeEnabledFromBuildMarker,
} from '../lib/intake-readiness-core.mjs';

const ALLOWED_HOSTS = new Set(['arcweb.onl', 'arcsites.netlify.app']);

function response(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow, noarchive',
  } });
}

export function createIntakeReadinessHandler(buildMarker = INTAKE_BUILD_MARKER, runtimeReady = intakeArc1RuntimeReady) {
  return async (request) => {
  if (request.method !== 'GET') return response(405, { error: 'method_not_allowed' });
  if (!ALLOWED_HOSTS.has(new URL(request.url).hostname)) return response(403, { error: 'forbidden' });
  const enabled = intakeEnabledFromBuildMarker(buildMarker) && process.env.ARC_BUILD_INTAKE_ENABLED === 'true' &&
    intakeEnabledFromAttestation(process.env[INTAKE_READINESS_ENV]) && intakeActivationReady(process.env) &&
    runtimeReady(request, process.env);
  return response(200, { schema: 'arc-intake-readiness-v1', intake_enabled: enabled });
  };
}

export default createIntakeReadinessHandler();

export const config = {
  path: '/api/intake/readiness', method: 'GET',
  rateLimit: { windowLimit: 60, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
