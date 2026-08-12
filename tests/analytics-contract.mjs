import assert from 'node:assert/strict';
import {
  aggregateAnalytics,
  eventKey,
  expirationTimestamp,
  isExpiredMetadata,
  normalizeAnalyticsEvent,
  RETENTION_DAYS,
} from '../netlify/lib/analytics-core.mjs';
import analyticsEventHandler, { config as eventConfig } from '../netlify/functions/analytics-event.mjs';
import analyticsDashboardHandler, { config as dashboardConfig } from '../netlify/functions/analytics-dashboard.mjs';

const now = new Date('2026-08-11T20:00:00.000Z');
const base = {
  event: 'arc_page_view',
  event_id: '11111111-1111-4111-8111-111111111111',
  session_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  path: '/',
};
const normalized = normalizeAnalyticsEvent(base, now);
assert.equal(normalized.received_at, now.toISOString());
assert.equal(eventKey(normalized), `events/${base.event_id}`);
assert.equal(expirationTimestamp(normalized.received_at), now.getTime() + RETENTION_DAYS * 86400000);
assert.equal(isExpiredMetadata({ expires_at: now.getTime() }, now), true);
assert.equal(isExpiredMetadata({ expires_at: now.getTime() + 1 }, now), false);

assert.throws(() => normalizeAnalyticsEvent({ ...base, email: 'person@example.com' }, now), /Unexpected analytics field/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'anything_else' }, now), /Unknown analytics event/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event_id: 'not-a-uuid' }, now), /event_id must be a UUID/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_cta_click', cta: '<script>alert(1)</script>' }, now), /allowlisted label/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', step: 2, step_name: 'John Smith' }, now), /exact allowlisted step label/);
assert.throws(() => normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request' }, now), /allowlisted page/);

const events = [
  normalized,
  normalizeAnalyticsEvent({ ...base, event: 'arc_cta_click', event_id: '22222222-2222-4222-8222-222222222222', cta: 'Get Free Preview' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', event_id: '33333333-3333-4333-8333-333333333333', step: 2, step_name: 'Offer' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_form_step', event_id: '44444444-4444-4444-8444-444444444444', step: 2, step_name: 'Offer' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request', event_id: '55555555-5555-4555-8555-555555555555', path: '/thank-you/' }, now),
  normalizeAnalyticsEvent({ ...base, event: 'arc_preview_request', event_id: '66666666-6666-4666-8666-666666666666', session_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', path: '/thank-you/' }, now),
];
const aggregate = aggregateAnalytics(events, now);
assert.equal(aggregate[7].counts.arc_page_view, 1);
assert.equal(aggregate[7].counts.arc_form_step, 1, 'Repeated steps from one session count once.');
assert.equal(aggregate[7].counts.arc_preview_request, 2);
assert.equal(aggregate[7].conversion_rate, 100, 'Request-only sessions must not inflate the viewed-session funnel.');

assert.equal(eventConfig.path, '/api/analytics/event');
assert.deepEqual(eventConfig.rateLimit.aggregateBy, ['ip', 'domain']);
assert.equal(dashboardConfig.path, '/internal/analytics');
const wrongHost = await analyticsEventHandler(new Request('https://example.com/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(base),
}));
assert.equal(wrongHost.status, 403);
const wrongType = await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify(base),
}));
assert.equal(wrongType.status, 415);
const badPayload = await analyticsEventHandler(new Request('https://arcweb.onl/api/analytics/event', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...base, email: 'person@example.com' }),
}));
assert.equal(badPayload.status, 400);

const savedUser = process.env.ARC_ANALYTICS_DASHBOARD_USER;
const savedPassword = process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
try {
  const unconfiguredDashboard = await analyticsDashboardHandler(new Request('https://arcweb.onl/internal/analytics'));
  assert.equal(unconfiguredDashboard.status, 503);
} finally {
  if (savedUser === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_USER;
  else process.env.ARC_ANALYTICS_DASHBOARD_USER = savedUser;
  if (savedPassword === undefined) delete process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD;
  else process.env.ARC_ANALYTICS_DASHBOARD_PASSWORD = savedPassword;
}

console.log('ARC analytics contract passed.');
