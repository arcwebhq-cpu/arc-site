import { createHash, createHmac, randomUUID } from 'node:crypto';
import { validateDecodableImageAsset } from './image-asset-validation.mjs';

export const INTAKE_STORE = 'arc-intake-submissions';
export const INTAKE_SUBMISSION_SCHEMA = 'arc-intake-function-submission-v1';
export const INTAKE_RESPONSE_SCHEMA = 'arc-intake-submission-accepted-v1';
export const INTAKE_ARC1_DELIVERY_SCHEMA = 'arc-intake-arc1-delivery-state-v1';
export const INTAKE_ARC1_DISPATCH_SCHEMA = 'arc-intake-arc1-dispatch-state-v1';
export const INTAKE_ASSET_REFERENCE_SCHEMA = 'arc-intake-private-asset-reference-v1';
export const INTAKE_VERSION = 'arc-intake-v7';
export const INTAKE_IDEMPOTENCY_SECRET_ENV = 'ARC_INTAKE_IDEMPOTENCY_SECRET';
export const INTAKE_REQUEST_ID_PREFIX = 'arc-intake-request-id-v1\n';
export const BUDGET_CONFIRMATION = 'Yes, understands the finished ARC website subtotal is $5,000 plus applicable sales tax only after preview approval';
export const TERMS_CONFIRMATION = 'Accepted ARC preview terms, privacy policy, refund policy, and service scope dated 2026-08-12; separate adult checkout acceptance required';
export const INTAKE_MAX_REQUEST_BYTES = 4_000_000;
export const INTAKE_MAX_FILE_BYTES = 1_250_000;
export const INTAKE_MAX_TOTAL_FILE_BYTES = 3_000_000;
export const INTAKE_MAX_TEXT_BYTES = 256 * 1024;

export const INTAKE_FILE_FIELDS = Object.freeze(['hero_image_file', 'logo_file', 'supporting_image_file']);
export const INTAKE_MULTI_FIELDS = Object.freeze(['assets', 'goals', 'lead_form_fields', 'proof', 'sections']);
export const INTAKE_SINGLE_FIELDS = Object.freeze([
  'asset_permission', 'brand_tone', 'budget_confirmed', 'business', 'business_hours',
  'business_story', 'city', 'colors', 'competitor_sites', 'cta_destination', 'design_dislikes', 'domain_status',
  'email', 'faqs_and_objections', 'features', 'final_notes', 'first_cta', 'form_started_at', 'highest_profit_service',
  'industry', 'intake_version', 'landing_path', 'last_step_reached', 'lead_form_needed', 'lead_notification_email',
  'main_call_to_action', 'main_offer', 'main_services', 'name', 'primary_style', 'public_address', 'public_email', 'public_phone',
  'reference_site_likes', 'referrer_host', 'social_links', 'target_customer', 'terms_accepted', 'utm_campaign',
  'utm_content', 'utm_medium', 'utm_source', 'utm_term', 'website', 'why_choose_you', 'proof_details', 'submission_request_id', 'bot-field',
]);
export const INTAKE_ALLOWED_FIELDS = Object.freeze([
  ...INTAKE_FILE_FIELDS,
  ...INTAKE_MULTI_FIELDS,
  ...INTAKE_SINGLE_FIELDS,
].sort());
const FILE_FIELDS = new Set(INTAKE_FILE_FIELDS);
const MULTI_FIELDS = new Set(INTAKE_MULTI_FIELDS);
const ALLOWED_FIELDS = new Set(INTAKE_ALLOWED_FIELDS);
const REQUIRED_FIELDS = Object.freeze([
  'business', 'city', 'email', 'industry', 'main_call_to_action', 'main_services', 'name', 'primary_style',
]);
const MAX_VALUES_PER_MULTI_FIELD = 16;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const CTA_VALUES = new Set(['Book Consultation', 'Call', 'Contact', 'Order or Reserve', 'Request Estimate']);
const PRIMARY_STYLE_VALUES = new Set(['Bold', 'Editorial', 'Luxury', 'Minimal', 'Modern', 'Warm and local']);
const LEAD_FORM_VALUES = new Set(['No', 'Yes']);
const ENUM_VALUES = Object.freeze({
  brand_tone: new Set(['Calm', 'Confident', 'Energetic', 'Friendly', 'Professional']),
  domain_status: new Set(['I need a domain', 'I own a domain', 'Not sure']),
  main_call_to_action: CTA_VALUES,
  primary_style: PRIMARY_STYLE_VALUES,
  lead_form_needed: LEAD_FORM_VALUES,
});
const MULTI_ENUM_VALUES = Object.freeze({
  assets: new Set(['Logo', 'None yet', 'Photos', 'Social links']),
  goals: new Set(['Bookings', 'Estimate requests', 'Explain services', 'Look more trusted', 'More calls', 'Sell or reserve online']),
  lead_form_fields: new Set(['Address', 'Budget', 'Email', 'Name', 'Phone', 'Preferred date', 'Project details', 'Service']),
  proof: new Set(['Awards or certifications', 'Case studies or results', 'Customer reviews', 'Licensed or insured', 'None yet', 'Years of experience']),
  sections: new Set(['About', 'Contact or quote form', 'FAQ', 'Gallery', 'Location and hours', 'Process', 'Reviews', 'Services']),
});
const EMAIL_FIELDS = Object.freeze(['email', 'lead_notification_email', 'public_email']);

export function intakeIdempotencyConfigured(env = process.env) {
  const secret = env[INTAKE_IDEMPOTENCY_SECRET_ENV];
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32 || Buffer.byteLength(secret, 'utf8') > 256) return false;
  return !Object.entries(env).some(([name, value]) => name !== INTAKE_IDEMPOTENCY_SECRET_ENV &&
    /(?:SECRET|TOKEN|PAT)$/.test(name) && typeof value === 'string' && value.length > 0 && value === secret);
}

export function createInitialArc1DeliveryState(receivedAt) {
  const nextAttemptAt = new Date(receivedAt);
  if (!Number.isFinite(nextAttemptAt.getTime())) throw new TypeError('Server time is invalid.');
  return {
    schema: INTAKE_ARC1_DELIVERY_SCHEMA,
    status: 'PENDING',
    attempt_count: 0,
    next_attempt_at: nextAttemptAt.toISOString(),
    lease_hmac_sha256: null,
    lease_expires_at: null,
    last_attempt_at: null,
    evidence_issued_at: null,
    evidence_expires_at: null,
    evidence_sha256: null,
    acknowledged_at: null,
    acknowledgement_sha256: null,
    consumer_claim_key_hmac_sha256: null,
    dead_lettered_at: null,
    alert_status: 'NONE',
    alert_code: null,
    alert_updated_at: null,
  };
}

export function createInitialArc1DispatchState() {
  return {
    schema: INTAKE_ARC1_DISPATCH_SCHEMA,
    status: 'PENDING',
    attempt_count: 0,
    attempt_lease_hmac_sha256: null,
    attempt_lease_expires_at: null,
    last_attempt_at: null,
    accepted_at: null,
    alert_status: 'NONE',
    alert_code: null,
    alert_updated_at: null,
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const isFile = (value) => value && typeof value === 'object' && typeof value.arrayBuffer === 'function' &&
  typeof value.type === 'string' && typeof value.size === 'number';

function scalar(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be text.`);
  const clean = value.trim();
  if (Buffer.byteLength(clean, 'utf8') > 20_000) throw new TypeError(`${field} is too large.`);
  if (CONTROL_CHARACTER_PATTERN.test(clean)) throw new TypeError(`${field} contains unsupported control characters.`);
  return clean;
}

function presentList(values, field) {
  const list = values.get(field);
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.some((value) => !value)) throw new TypeError(`${field} contains an empty value.`);
  if (new Set(list).size !== list.length) throw new TypeError(`${field} contains duplicate values.`);
  return list;
}

function validEmail(value) {
  return typeof value === 'string' && value.length <= 254 && EMAIL_PATTERN.test(value);
}

function validHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

function validatePublicBrief(values, files) {
  for (const field of EMAIL_FIELDS) {
    const value = values.get(field);
    if (value && !validEmail(value)) throw new TypeError(`${field} is invalid.`);
  }
  if (values.get('website') && !validHttpUrl(values.get('website'))) throw new TypeError('website is invalid.');

  for (const [field, allowed] of Object.entries(ENUM_VALUES)) {
    const value = values.get(field);
    if (value && !allowed.has(value)) throw new TypeError(`${field} is invalid.`);
  }
  for (const [field, allowed] of Object.entries(MULTI_ENUM_VALUES)) {
    for (const value of presentList(values, field)) {
      if (!allowed.has(value)) throw new TypeError(`${field} is invalid.`);
    }
  }

  const goals = presentList(values, 'goals');
  const sections = presentList(values, 'sections');
  if (!goals.length) throw new TypeError('Intake goals are required.');
  if (!sections.length) throw new TypeError('Intake website sections are required.');

  for (const field of ['assets', 'proof']) {
    const selected = presentList(values, field);
    if (selected.includes('None yet') && selected.length !== 1) throw new TypeError(`${field} has conflicting values.`);
  }

  const cta = values.get('main_call_to_action');
  const leadChoice = values.get('lead_form_needed');
  const impliedLeadForm = cta === 'Request Estimate' || cta === 'Contact';
  const includesLeadForm = impliedLeadForm || leadChoice === 'Yes';
  if (!leadChoice || (impliedLeadForm && leadChoice !== 'Yes')) throw new TypeError('Lead-form choice is invalid.');
  if (sections.includes('Contact or quote form') && !includesLeadForm) {
    throw new TypeError('A contact-form section requires lead routing.');
  }
  if (includesLeadForm) {
    if (leadChoice !== 'Yes' || !validEmail(values.get('lead_notification_email')) ||
        !presentList(values, 'lead_form_fields').length) {
      throw new TypeError('Verified lead routing details are required.');
    }
  }

  const ctaDestination = values.get('cta_destination');
  if (cta === 'Call') {
    const digits = String(ctaDestination || '').replace(/\D/g, '');
    if (digits.length < 7 || digits.length > 15) throw new TypeError('Call destination is invalid.');
  }
  if ((cta === 'Book Consultation' || cta === 'Order or Reserve') && !validHttpUrl(ctaDestination)) {
    throw new TypeError('CTA destination is invalid.');
  }

  const proof = presentList(values, 'proof');
  if (proof.some((value) => value !== 'None yet') && !values.get('proof_details')) {
    throw new TypeError('Exact proof details are required.');
  }
  const assets = presentList(values, 'assets');
  const hasSubmittedAsset = files.size > 0;
  if ((hasSubmittedAsset || assets.includes('Logo') || assets.includes('Photos')) && values.get('asset_permission') !== 'Confirmed') {
    throw new TypeError('Exact asset permission is required for submitted assets.');
  }
  if (files.has('logo_file') && !assets.includes('Logo')) throw new TypeError('Logo upload is missing its asset selection.');
  if ((files.has('hero_image_file') || files.has('supporting_image_file')) && !assets.includes('Photos')) {
    throw new TypeError('Photo upload is missing its asset selection.');
  }
}

function deterministicSubmissionIdentity(requestId, secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32 || Buffer.byteLength(secret, 'utf8') > 256) {
    throw new TypeError('Intake idempotency secret is unavailable.');
  }
  const digest = createHmac('sha256', secret).update(`${INTAKE_REQUEST_ID_PREFIX}${requestId}`).digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function normalizeIntakeForm(formData, now = new Date(), uuid = randomUUID, options = {}) {
  if (!formData || typeof formData.entries !== 'function') throw new TypeError('Multipart form data is required.');
  const values = new Map();
  const files = new Map();
  let textBytes = 0;
  for (const [field, raw] of formData.entries()) {
    if (!ALLOWED_FIELDS.has(field)) throw new TypeError('Unexpected intake field.');
    if (isFile(raw)) {
      if (!FILE_FIELDS.has(field) || files.has(field)) throw new TypeError('Unexpected or duplicate intake file.');
      if (raw.size === 0 && !String(raw.name || '')) continue;
      files.set(field, raw);
      continue;
    }
    if (FILE_FIELDS.has(field)) throw new TypeError('Intake file field must contain a file.');
    const clean = scalar(raw, field);
    textBytes += Buffer.byteLength(clean, 'utf8');
    if (textBytes > INTAKE_MAX_TEXT_BYTES) throw new TypeError('Intake text is too large.');
    if (MULTI_FIELDS.has(field)) {
      const list = values.get(field) || [];
      if (list.length >= MAX_VALUES_PER_MULTI_FIELD) throw new TypeError('Too many intake values.');
      list.push(clean);
      values.set(field, list);
    } else {
      if (values.has(field)) throw new TypeError('Duplicate intake field.');
      values.set(field, clean);
    }
  }

  if (values.get('bot-field')) throw new TypeError('Automated intake rejected.');
  values.delete('bot-field');
  if (values.get('intake_version') !== INTAKE_VERSION || values.get('budget_confirmed') !== BUDGET_CONFIRMATION ||
      values.get('terms_accepted') !== TERMS_CONFIRMATION) throw new TypeError('Intake consent or version is invalid.');
  for (const field of REQUIRED_FIELDS) if (!values.get(field)) throw new TypeError(`Required intake field is missing: ${field}.`);
  const requestId = values.get('submission_request_id');
  if ((requestId || options.idempotencySecret) && !UUID_PATTERN.test(String(requestId || ''))) {
    throw new TypeError('Intake request identity is invalid.');
  }
  validatePublicBrief(values, files);

  const assets = [];
  let totalFileBytes = 0;
  const sortedFileFields = [...files.keys()].sort();
  for (const field of sortedFileFields) {
    const file = files.get(field);
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > INTAKE_MAX_FILE_BYTES) throw new TypeError('Intake file size is invalid.');
    totalFileBytes += file.size;
    if (totalFileBytes > INTAKE_MAX_TOTAL_FILE_BYTES) throw new TypeError('Intake files are too large.');
  }
  for (const field of sortedFileFields) {
    const file = files.get(field);
    const bytes = Buffer.from(await file.arrayBuffer());
    if (bytes.length !== file.size) throw new TypeError('Intake file type does not match its bytes.');
    await validateDecodableImageAsset(bytes, file.type);
    assets.push({
      schema: INTAKE_ASSET_REFERENCE_SCHEMA,
      kind: 'UPLOAD',
      role: field,
      content_type: file.type,
      size: bytes.length,
      sha256: sha256(bytes),
      content_base64: bytes.toString('base64'),
    });
  }

  const receivedAt = new Date(now);
  if (!Number.isFinite(receivedAt.getTime())) throw new TypeError('Server time is invalid.');
  const submissionId = options.idempotencySecret
    ? deterministicSubmissionIdentity(requestId, options.idempotencySecret)
    : uuid();
  if (!UUID_PATTERN.test(submissionId)) throw new TypeError('Secure submission identity is unavailable.');
  values.delete('submission_request_id');
  const data = Object.fromEntries([...values.entries()].sort(([left], [right]) => left.localeCompare(right)));
  assets.sort((left, right) => left.role.localeCompare(right.role));
  const manifest = assets.map(({ content_base64, content_utf8, ...asset }) => asset);
  const submissionDataSha256 = sha256(canonicalJson({ data, asset_manifest: manifest }));
  return {
    key: `submissions/${submissionId}`,
    record: {
      schema: INTAKE_SUBMISSION_SCHEMA,
      submission_id: submissionId,
      received_at: receivedAt.toISOString(),
      source: 'first-party-netlify-function',
      form_name: 'arc-preview-function-v1',
      submission_data_sha256: submissionDataSha256,
      data,
      asset_manifest: manifest,
      // Raw upload bytes stay only in this private source record. The bridge
      // receives content-addressed retrieval grants, never inline bytes.
      assets,
      arc1_consumer_compatible: false,
      arc1_delivery: createInitialArc1DeliveryState(receivedAt),
      arc1_dispatch: createInitialArc1DispatchState(),
    },
  };
}
