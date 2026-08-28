const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const HTTPS_ORIGIN = 'https://arcweb.onl';

export const TRANSACTIONAL_EMAIL_TEMPLATE_VERSION = 'arc-transactional-email-templates-v1';
export const TRANSACTIONAL_EMAIL_KINDS = Object.freeze([
  'intake_confirmation',
  'preview_review',
  'operations_alert',
  'claim_invitation',
  'final_delivery',
]);

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function text(value, label, maximum = 256) {
  if (typeof value !== 'string' || value.length < 1 || value !== value.trim() ||
      Buffer.byteLength(value, 'utf8') > maximum || CONTROL.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function email(value) {
  const normalized = text(value, 'Transactional email recipient', 254).toLowerCase();
  if (!EMAIL.test(normalized)) throw new TypeError('Transactional email recipient is invalid.');
  return normalized;
}

function url(value, label, options = {}) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError(`${label} is invalid.`); }
  const validHash = !parsed.hash ||
    options.inviteFragment && /^#invite=[A-Za-z0-9_-]{24,192}$/.test(parsed.hash) ||
    options.verificationFragment && /^#arcv1\.[A-Za-z0-9_-]{43}$/.test(parsed.hash) ||
    options.claimFragment && /^#arc2\.[a-f0-9]{64}\.[A-Za-z0-9_-]{24,192}$/.test(parsed.hash);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port || !validHash ||
      (options.arcOnly && parsed.origin !== HTTPS_ORIGIN)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return parsed.toString();
}

function escapeHtml(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function layout(heading, paragraphs, action = null) {
  const body = paragraphs.map((paragraph) => `<p style="margin:0 0 16px">${paragraph}</p>`).join('');
  const button = action ? `<p style="margin:24px 0"><a href="${escapeHtml(action.url)}" ` +
    'style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:14px 20px;border-radius:8px;font-weight:700">' +
    `${escapeHtml(action.label)}</a></p>` : '';
  return '<!doctype html><html><body style="margin:0;background:#f5f5f3;color:#111;font-family:Arial,sans-serif">' +
    '<div style="max-width:600px;margin:0 auto;padding:32px 20px">' +
    '<div style="background:#fff;border:1px solid #ddd;border-radius:12px;padding:28px">' +
    `<p style="margin:0 0 20px;font-weight:800;letter-spacing:.08em">ARC WEB</p>` +
    `<h1 style="font-size:26px;line-height:1.2;margin:0 0 18px">${escapeHtml(heading)}</h1>${body}${button}` +
    '<p style="font-size:12px;color:#666;margin:24px 0 0">No reply is needed.</p>' +
    '</div></div></body></html>';
}

function result(kind, recipient, subject, plain, html) {
  return Object.freeze({
    template_version: TRANSACTIONAL_EMAIL_TEMPLATE_VERSION,
    kind,
    to: recipient,
    subject,
    text: plain,
    html,
  });
}

export function renderTransactionalEmail(kind, input) {
  if (!TRANSACTIONAL_EMAIL_KINDS.includes(kind)) throw new TypeError('Transactional email kind is invalid.');
  if (kind === 'intake_confirmation') {
    if (!exactKeys(input, ['recipient_email', 'verification_url'])) {
      throw new TypeError('Intake confirmation template input is invalid.');
    }
    const recipient = email(input.recipient_email);
    const verificationUrl = url(input.verification_url, 'Intake verification URL', {
      arcOnly: true, verificationFragment: true,
    });
    if (new URL(verificationUrl).pathname !== '/verify/') throw new TypeError('Intake verification URL is invalid.');
    const subject = 'Confirm your email to start your free preview';
    const first = 'Your details are in. Confirm your email to start your free website preview.';
    const second = '<strong>No payment is due unless you approve it.</strong>';
    return result(kind, recipient, subject,
      `Your details are in. Confirm your email to start your free website preview: ${verificationUrl} We will email the preview when it is ready. No payment is due unless you approve it. No reply is needed.`,
      layout('Confirm your email', [first, 'We will email the preview when it is ready.', second],
        { url: verificationUrl, label: 'Confirm email' }));
  }
  if (kind === 'preview_review') {
    if (!exactKeys(input, ['recipient_email', 'review_url'])) throw new TypeError('Preview review template input is invalid.');
    const recipient = email(input.recipient_email);
    const reviewUrl = url(input.review_url, 'Preview review URL', { arcOnly: true, inviteFragment: true });
    const subject = 'Your free website preview is ready';
    return result(kind, recipient, subject,
      `Your free website preview is ready. See the website before you pay: ${reviewUrl} Approve it only if you want to move forward. No reply is needed.`,
      layout('Your free preview is ready', ['See the website before you pay.', 'Approve it only if you want to move forward.'],
        { url: reviewUrl, label: 'Review your preview' }));
  }
  if (kind === 'operations_alert') {
    if (!exactKeys(input, ['category', 'detail_code', 'detected_at', 'recipient_email', 'severity'])) {
      throw new TypeError('Operations alert template input is invalid.');
    }
    const recipient = email(input.recipient_email);
    const severity = text(input.severity, 'Operations alert severity', 16).toUpperCase();
    if (!['HIGH', 'CRITICAL'].includes(severity)) throw new TypeError('Operations alert severity is invalid.');
    const category = text(input.category, 'Operations alert category', 64);
    const detail = text(input.detail_code, 'Operations alert detail', 128);
    const detected = new Date(input.detected_at);
    if (!Number.isFinite(detected.getTime()) || detected.toISOString() !== input.detected_at) {
      throw new TypeError('Operations alert timestamp is invalid.');
    }
    const subject = `[ARC ${severity}] ${category}`;
    const sentence = `ARC detected ${detail} at ${detected.toISOString()}. Review operations before retrying automation.`;
    return result(kind, recipient, subject, `${sentence} No reply is needed.`,
      layout('Automation needs review', [escapeHtml(sentence)]));
  }
  if (kind === 'claim_invitation') {
    if (!exactKeys(input, ['claim_url', 'recipient_email'])) {
      throw new TypeError('Claim invitation template input is invalid.');
    }
    const recipient = email(input.recipient_email);
    const claimUrl = url(input.claim_url, 'Claim invitation URL', { arcOnly: true, claimFragment: true });
    const subject = 'Claim your approved website';
    return result(kind, recipient, subject,
      `Your approved website is ready to claim: ${claimUrl} No reply is needed.`,
      layout('Claim your approved website', ['Transfer the approved website to your Netlify account.'],
        { url: claimUrl, label: 'Claim your website' }));
  }
  if (!exactKeys(input, ['production_url', 'recipient_email'])) {
    throw new TypeError('Final delivery template input is invalid.');
  }
  const recipient = email(input.recipient_email);
  const productionUrl = url(input.production_url, 'Final production URL');
  const subject = 'Your website is live';
  return result(kind, recipient, subject,
    `Your website is live: ${productionUrl} No reply is needed.`,
    layout('Your website is live', ['Your approved website has been delivered.'],
      { url: productionUrl, label: 'Open your website' }));
}
