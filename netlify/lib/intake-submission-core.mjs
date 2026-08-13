import { createHash, randomUUID } from 'node:crypto';

export const INTAKE_STORE = 'arc-intake-submissions';
export const INTAKE_SUBMISSION_SCHEMA = 'arc-intake-function-submission-v1';
export const INTAKE_RESPONSE_SCHEMA = 'arc-intake-submission-accepted-v1';
export const INTAKE_VERSION = 'arc-intake-v7';
export const BUDGET_CONFIRMATION = 'Yes, understands the finished ARC website subtotal is $5,000 plus applicable sales tax only after preview approval';
export const TERMS_CONFIRMATION = 'Accepted ARC preview terms, privacy policy, refund policy, and service scope dated 2026-08-12; separate adult checkout acceptance required';
export const INTAKE_MAX_REQUEST_BYTES = 4_000_000;
export const INTAKE_MAX_FILE_BYTES = 1_250_000;
export const INTAKE_MAX_TOTAL_FILE_BYTES = 3_000_000;
export const INTAKE_MAX_TEXT_BYTES = 256 * 1024;

export const INTAKE_FILE_FIELDS = Object.freeze(['hero_image_file', 'logo_file', 'supporting_image_file']);
export const INTAKE_MULTI_FIELDS = Object.freeze(['assets', 'goals', 'lead_form_fields', 'proof', 'sections']);
export const INTAKE_SINGLE_FIELDS = Object.freeze([
  'asset_folder_link', 'asset_permission', 'brand_tone', 'budget_confirmed', 'business', 'business_hours',
  'business_story', 'city', 'colors', 'competitor_sites', 'cta_destination', 'design_dislikes', 'domain_status',
  'email', 'faqs_and_objections', 'features', 'final_notes', 'first_cta', 'form_started_at', 'highest_profit_service',
  'industry', 'intake_version', 'landing_path', 'last_step_reached', 'lead_form_needed', 'lead_notification_email',
  'main_call_to_action', 'main_offer', 'main_services', 'name', 'primary_style', 'public_address', 'public_email', 'public_phone',
  'reference_site_likes', 'referrer_host', 'social_links', 'target_customer', 'terms_accepted', 'utm_campaign',
  'utm_content', 'utm_medium', 'utm_source', 'utm_term', 'website', 'why_choose_you', 'proof_details', 'bot-field',
]);
export const INTAKE_ALLOWED_FIELDS = Object.freeze([
  ...INTAKE_FILE_FIELDS,
  ...INTAKE_MULTI_FIELDS,
  ...INTAKE_SINGLE_FIELDS,
].sort());
const FILE_FIELDS = new Set(INTAKE_FILE_FIELDS);
const MULTI_FIELDS = new Set(INTAKE_MULTI_FIELDS);
const ALLOWED_FIELDS = new Set(INTAKE_ALLOWED_FIELDS);
const REQUIRED_FIELDS = Object.freeze(['business', 'city', 'email', 'industry', 'main_call_to_action', 'main_services', 'name']);
const MAX_VALUES_PER_MULTI_FIELD = 16;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

function validMagic(bytes, type) {
  if (type === 'image/png') return bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (type === 'image/jpeg') return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (type === 'image/webp') return bytes.length >= 12 && bytes.subarray(0, 4).toString() === 'RIFF' && bytes.subarray(8, 12).toString() === 'WEBP';
  return false;
}

function scalar(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be text.`);
  const clean = value.trim();
  if (Buffer.byteLength(clean, 'utf8') > 20_000) throw new TypeError(`${field} is too large.`);
  return clean;
}

export async function normalizeIntakeForm(formData, now = new Date(), uuid = randomUUID) {
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
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.get('email')) || values.get('email').length > 254) {
    throw new TypeError('Intake email is invalid.');
  }
  if (!Array.isArray(values.get('goals')) || values.get('goals').filter(Boolean).length === 0) throw new TypeError('Intake goals are required.');
  if ((files.size > 0 || Boolean(values.get('asset_folder_link'))) && values.get('asset_permission') !== 'Confirmed') {
    throw new TypeError('Exact asset permission is required for submitted assets.');
  }

  const assets = [];
  let totalFileBytes = 0;
  for (const field of [...files.keys()].sort()) {
    const file = files.get(field);
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > INTAKE_MAX_FILE_BYTES) throw new TypeError('Intake file size is invalid.');
    totalFileBytes += file.size;
    if (totalFileBytes > INTAKE_MAX_TOTAL_FILE_BYTES) throw new TypeError('Intake files are too large.');
    const bytes = Buffer.from(await file.arrayBuffer());
    if (bytes.length !== file.size || !validMagic(bytes, file.type)) throw new TypeError('Intake file type does not match its bytes.');
    assets.push({ field, content_type: file.type, size: bytes.length, sha256: sha256(bytes), content_base64: bytes.toString('base64') });
  }

  const receivedAt = new Date(now);
  if (!Number.isFinite(receivedAt.getTime())) throw new TypeError('Server time is invalid.');
  const submissionId = uuid();
  if (!UUID_PATTERN.test(submissionId)) throw new TypeError('Secure submission identity is unavailable.');
  const data = Object.fromEntries([...values.entries()].sort(([left], [right]) => left.localeCompare(right)));
  const manifest = assets.map(({ content_base64, ...asset }) => asset);
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
      assets,
      arc1_consumer_compatible: false,
    },
  };
}
