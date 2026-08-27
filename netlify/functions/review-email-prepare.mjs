import { getStore } from '@netlify/blobs';

import {
  prepareReviewInviteEmail,
  renewExpiredReadyReviewEmail,
} from '../lib/review-email-outbox-core.mjs';
import {
  readAuthenticatedReviewEmailJson,
  reviewEmailInternalApiConfiguration,
  reviewEmailInternalHttpError,
} from '../lib/review-email-http-core.mjs';
import { REVIEW_STORE } from '../lib/review-flow-core.mjs';
import { reviewJsonResponse } from '../lib/review-http-core.mjs';

const PATH = '/api/internal/review-email/prepare';
const INVITE_FIELDS = Object.freeze([
  'brief_sha256', 'expires_at', 'invite_token', 'page_bindings', 'preview_content_sha256',
  'preview_manifest_sha256', 'preview_source_commit_sha', 'preview_source_repository', 'preview_url',
  'prior_invite_hmac_sha256', 'recipient_email_sha256', 'scope_version',
]);

function exactFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

export default async (request, context = {}) => {
  if (!reviewEmailInternalApiConfiguration(process.env).enabled) {
    return reviewJsonResponse(503, { error: 'review_email_worker_disabled' });
  }
  if (request.method !== 'POST') return reviewJsonResponse(405, { error: 'method_not_allowed' });
  try {
    const value = await readAuthenticatedReviewEmailJson(request, PATH, 20_000, process.env, {
      clock: context.clock,
    });
    const prepare = exactFields(value, ['invite']) ||
      exactFields(value, ['invite', 'source_reference_hmac_sha256']);
    const renew = exactFields(value, ['invite', 'replaced_invite_hmac_sha256']) ||
      exactFields(value, ['invite', 'replaced_invite_hmac_sha256', 'source_reference_hmac_sha256']);
    if ((!prepare && !renew) || !exactFields(value.invite, INVITE_FIELDS)) {
      throw new TypeError('Review email preparation fields are invalid.');
    }
    const store = context.reviewStore || getStore({ name: REVIEW_STORE, consistency: 'strong' });
    const result = renew
      ? await renewExpiredReadyReviewEmail(store, value.replaced_invite_hmac_sha256,
        value.invite, process.env, {
          clock: context.clock,
          sourceReferenceHmacSha256: value.source_reference_hmac_sha256,
        })
      : await prepareReviewInviteEmail(store, value.invite, process.env, {
        clock: context.clock,
        sourceReferenceHmacSha256: value.source_reference_hmac_sha256,
      });
    return reviewJsonResponse(200, {
      idempotent_replay: result.idempotent_replay,
      invite_hmac_sha256: result.invite.invite_hmac_sha256,
      outbox_hmac_sha256: result.outbox.outbox_hmac_sha256,
      prepared: true,
      renewed: renew,
      state: result.outbox.state,
    });
  } catch (error) {
    const [status, code] = reviewEmailInternalHttpError(error);
    return reviewJsonResponse(status, { error: code });
  }
};

export const config = {
  path: '/api/internal/review-email/prepare', method: 'POST',
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
