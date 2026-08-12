export const ANALYTICS_SCHEMA = 'arc-analytics-event-v1';
export const ANALYTICS_STORE = 'arc-analytics';
export const RETENTION_DAYS = 90;
export const EVENT_NAMES = Object.freeze([
  'arc_page_view',
  'arc_cta_click',
  'arc_form_start',
  'arc_form_step',
  'arc_preview_request',
]);

const EVENT_SET = new Set(EVENT_NAMES);
const ALLOWED_KEYS = new Set(['event', 'event_id', 'session_id', 'path', 'cta', 'step', 'step_name']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PATH_PATTERN = /^\/[a-z0-9/_-]{0,119}$/i;
const CTA_LABELS = new Set(['Get Free Preview', 'Build My Free Preview']);
const STEP_LABELS = Object.freeze({ 1: 'Business', 2: 'Offer', 3: 'Details & consent', 4: 'Review' });

function requirePlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('Analytics payload must be a plain object.');
  }
}

function requireUuid(value, field) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw new TypeError(`${field} must be a UUID.`);
  return value.toLowerCase();
}

export function normalizeAnalyticsEvent(input, now = new Date()) {
  requirePlainObject(input);
  for (const key of Object.keys(input)) {
    if (!ALLOWED_KEYS.has(key)) throw new TypeError(`Unexpected analytics field: ${key}`);
  }

  if (!EVENT_SET.has(input.event)) throw new TypeError('Unknown analytics event.');
  const receivedAt = new Date(now);
  if (!Number.isFinite(receivedAt.getTime())) throw new TypeError('Invalid server timestamp.');
  if (typeof input.path !== 'string' || !PATH_PATTERN.test(input.path)) throw new TypeError('Invalid analytics path.');

  const event = {
    schema: ANALYTICS_SCHEMA,
    event: input.event,
    event_id: requireUuid(input.event_id, 'event_id'),
    session_id: requireUuid(input.session_id, 'session_id'),
    path: input.path,
    received_at: receivedAt.toISOString(),
  };

  if (input.step !== undefined) {
    if (!Number.isInteger(input.step) || input.step < 1 || input.step > 4) throw new TypeError('step must be an integer from 1 to 4.');
    event.step = input.step;
  }

  if (input.event === 'arc_cta_click') {
    if (!CTA_LABELS.has(input.cta)) throw new TypeError('CTA events require an allowlisted label.');
    event.cta = input.cta;
  } else if (input.cta !== undefined) throw new TypeError('cta is allowed only for CTA events.');

  if (input.event === 'arc_form_step') {
    if (!event.step || input.step_name !== STEP_LABELS[event.step]) throw new TypeError('Form-step events require the exact allowlisted step label.');
    event.step_name = input.step_name;
  } else if (input.step !== undefined || input.step_name !== undefined) throw new TypeError('Step fields are allowed only for form-step events.');

  const expectedPath = input.event === 'arc_preview_request' ? '/thank-you/' : '/';
  if (input.path !== expectedPath) throw new TypeError('Event path does not match its allowlisted page.');
  return event;
}

export function eventKey(event) {
  return `events/${event.event_id}`;
}

export function expirationTimestamp(receivedAt) {
  const started = new Date(receivedAt).getTime();
  if (!Number.isFinite(started)) throw new TypeError('Invalid received timestamp.');
  return started + RETENTION_DAYS * 24 * 60 * 60 * 1000;
}

export function isExpiredMetadata(metadata, now = new Date()) {
  const expiry = Number(metadata?.expires_at);
  return Number.isFinite(expiry) && expiry <= new Date(now).getTime();
}

export function aggregateAnalytics(events, now = new Date()) {
  const currentTime = new Date(now).getTime();
  if (!Number.isFinite(currentTime)) throw new TypeError('Invalid aggregation timestamp.');
  const periods = {};
  for (const days of [7, 30, 90]) {
    const start = currentTime - days * 24 * 60 * 60 * 1000;
    const matching = events.filter((event) => {
      const timestamp = Date.parse(event?.received_at || '');
      return EVENT_SET.has(event?.event) && typeof event?.session_id === 'string' && UUID_PATTERN.test(event.session_id) && Number.isFinite(timestamp) && timestamp >= start && timestamp <= currentTime;
    });
    const uniqueByEvent = Object.fromEntries(EVENT_NAMES.map((name) => [name, new Set()]));
    for (const event of matching) uniqueByEvent[event.event].add(event.session_id);
    const counts = Object.fromEntries(EVENT_NAMES.map((name) => [name, uniqueByEvent[name].size]));
    const views = counts.arc_page_view;
    const requestsFromViewedSessions = [...uniqueByEvent.arc_preview_request].filter((sessionId) => uniqueByEvent.arc_page_view.has(sessionId)).length;
    periods[days] = {
      counts,
      conversion_rate: views ? Number(((requestsFromViewedSessions / views) * 100).toFixed(1)) : 0,
    };
  }
  return periods;
}
