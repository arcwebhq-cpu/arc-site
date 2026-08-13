export const INTAKE_READINESS_ENV = 'ARC_INTAKE_READINESS_ATTESTATION';
export const INTAKE_READINESS_SCHEMA = 'arc-intake-readiness-attestation-v1';
export const INTAKE_READINESS_VERSION = 1;
export const INTAKE_BUILD_MARKER_SCHEMA = 'arc-intake-build-marker-v1';
export const INTAKE_BUILD_MARKER_VERSION = 1;

export const INTAKE_READINESS_BOOLEAN_FIELDS = Object.freeze([
  'intake_enabled',
  'route_verified',
  'recipient_verified',
  'dedupe_verified',
  'failure_alert_verified',
  'transactional_sender_verified',
  'adult_operator_verified',
  'legal_readiness_verified',
  'tax_readiness_verified',
  'payment_readiness_verified',
  'arc1_consumer_adapter_verified',
  'native_netlify_forms_disabled_verified',
  'retention_verified',
  'asset_pipeline_verified',
]);

const EXACT_KEYS = Object.freeze([
  'schema',
  'version',
  ...INTAKE_READINESS_BOOLEAN_FIELDS,
].sort());
const MAX_ATTESTATION_BYTES = 2048;

export function intakeEnabledFromBuildMarker(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['intake_enabled', 'schema', 'version'])) return false;
  return value.schema === INTAKE_BUILD_MARKER_SCHEMA && value.version === INTAKE_BUILD_MARKER_VERSION &&
    value.intake_enabled === true;
}

export function intakeEnabledFromAttestation(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || Buffer.byteLength(raw, 'utf8') > MAX_ATTESTATION_BYTES) {
    return false;
  }

  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return false;
  }

  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(EXACT_KEYS)) return false;
  if (value.schema !== INTAKE_READINESS_SCHEMA || value.version !== INTAKE_READINESS_VERSION) return false;
  if (INTAKE_READINESS_BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean')) return false;

  return INTAKE_READINESS_BOOLEAN_FIELDS.every((field) => value[field] === true);
}
