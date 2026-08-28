import { getStore } from '@netlify/blobs';

import {
  canonicalJson,
  hmacHex,
  safeEqual,
  sha256Hex,
} from './arc2-handoff-core.mjs';
import {
  RETENTION_GENERATION_FENCE_SECRET_ENV,
  RETENTION_GENERATION_FENCE_STORE,
  ensureRetentionGenerationFence,
  retentionGenerationFenceConfiguration,
  runRetentionProducerOperation,
} from './retention-generation-fence-core.mjs';
import {
  buildFirstPartyLegalHoldRecord,
  firstPartyLegalHoldKey,
} from './first-party-retention-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  './retention-generation-fence-alert-queue-core.mjs';

export const RETENTION_ROUTE_OUTPUT_SCHEMA = 'arc-first-party-retention-route-output-v1';
export const RETENTION_ROUTE_OUTPUT_PREFIX =
  'first-party-retention/generation-fence/route-outputs/';

const OUTPUT_SIGNATURE_DOMAIN = 'arc-first-party-retention-route-output-record-v1';
const REQUEST_SOURCE_SCHEMA = 'arc-first-party-retention-route-request-source-v1';
const MUTATION_SCHEMA = 'arc-first-party-retention-route-mutation-v1';
const OUTPUT_IDENTITY_SCHEMA = 'arc-first-party-retention-route-output-identity-v1';
const LEGAL_HOLD_REQUEST_SOURCE_SCHEMA =
  'arc-first-party-retention-legal-hold-request-source-v1';
const LEGAL_HOLD_MUTATION_SCHEMA = 'arc-first-party-retention-legal-hold-mutation-v1';
const ROUTE = /^[a-z0-9][a-z0-9._:/-]{0,159}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const MAX_REQUEST_BYTES = 5_242_880;
const MISSING_OUTPUT_SHA256 = '0'.repeat(64);
const IDEMPOTENCY_HEADERS = Object.freeze([
  'authorization',
  'cookie',
  'idempotency-key',
  'svix-id',
  'x-arc-handoff-id',
  'x-arc-idempotency-key',
  'x-idempotency-key',
]);
const OUTPUT_FIELDS = Object.freeze([
  'completed_at', 'customer_data_stored', 'generation', 'idempotency_key_sha256',
  'method', 'operation_hmac_sha256', 'output_record_sha256', 'path_sha256',
  'record_hmac_sha256', 'request_sha256', 'response_body_sha256', 'response_status',
  'route', 'schema', 'version',
]);

function exactKeys(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}

function hex64(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) throw new TypeError(`${label} is invalid.`);
  return value;
}

function nowDate(context) {
  const clock = context.retentionFenceClock || context.clock || (() => new Date());
  const value = new Date(clock());
  if (!Number.isFinite(value.getTime())) throw new TypeError('Retention route clock is invalid.');
  return value;
}

function json(status, value) {
  return new Response(JSON.stringify(value), { status, headers: {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  } });
}

function responseBodyDigest(response) {
  return response.clone().arrayBuffer().then((body) => sha256Hex(Buffer.from(body)));
}

function requestPath(request) {
  try { return new URL(request.url).pathname; }
  catch { throw new TypeError('Retention route request URL is invalid.'); }
}

function requestTarget(request) {
  try {
    const url = new URL(request.url);
    return `${url.pathname}${url.search}`;
  } catch {
    throw new TypeError('Retention route request URL is invalid.');
  }
}

function hashedIdempotencyHeaders(request) {
  const values = {};
  for (const name of IDEMPOTENCY_HEADERS) {
    const value = request.headers.get(name);
    if (typeof value === 'string' && value.length > 0) {
      values[name] = sha256Hex(value);
    }
  }
  return sha256Hex(canonicalJson(values));
}

async function boundedRequestBody(request, maximumBytes) {
  const clone = request.clone();
  const declared = clone.headers.get('content-length');
  if (declared !== null && (!/^\d{1,8}$/.test(declared) || Number(declared) > maximumBytes)) {
    await Promise.allSettled([
      clone.body?.cancel?.(),
      request.body?.cancel?.(),
    ].filter(Boolean));
    throw new RangeError('Retention route request is too large.');
  }
  const reader = clone.body?.getReader?.();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new TypeError('Retention route request body is invalid.');
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        // Request.clone() tees the body. Cancel both branches together so a
        // headerless oversized stream cannot leave either cancellation waiting
        // forever on its peer branch.
        await Promise.allSettled([
          reader.cancel(),
          request.body?.cancel?.(),
        ].filter(Boolean));
        throw new RangeError('Retention route request is too large.');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, total);
}

async function readRequestIdentity(request, maximumBytes = MAX_REQUEST_BYTES) {
  if (!request || typeof request.clone !== 'function' || typeof request.url !== 'string') {
    throw new TypeError('Retention route request is invalid.');
  }
  const body = await boundedRequestBody(request, maximumBytes);
  const method = String(request.method || '').toUpperCase();
  const path = requestPath(request);
  const target = requestTarget(request);
  const idempotencyKeySha256 = hashedIdempotencyHeaders(request);
  const bodySha256 = sha256Hex(body);
  const source = {
    schema: REQUEST_SOURCE_SCHEMA,
    method,
    path_sha256: sha256Hex(target),
    body_sha256: bodySha256,
    idempotency_key_sha256: idempotencyKeySha256,
  };
  return Object.freeze({
    method,
    path,
    path_sha256: source.path_sha256,
    body_sha256: bodySha256,
    idempotency_key_sha256: idempotencyKeySha256,
    source_record_sha256: sha256Hex(canonicalJson(source)),
  });
}

function routeDescriptor(route, identity, generation, secret) {
  const mutation = {
    schema: MUTATION_SCHEMA,
    route,
    method: identity.method,
    path_sha256: identity.path_sha256,
    request_sha256: identity.source_record_sha256,
    idempotency_key_sha256: identity.idempotency_key_sha256,
    generation_binding: generation,
  };
  const output = {
    schema: OUTPUT_IDENTITY_SCHEMA,
    route,
    request_sha256: identity.source_record_sha256,
    mutation_sha256: sha256Hex(canonicalJson(mutation)),
  };
  return Object.freeze({
    route,
    subject_hmac_sha256: hmacHex(secret,
      `arc-first-party-retention-route-subject-v1\n${identity.source_record_sha256}`),
    idempotency_key_sha256: identity.idempotency_key_sha256,
    source_record_sha256: identity.source_record_sha256,
    mutation_sha256: output.mutation_sha256,
    output_record_sha256: sha256Hex(canonicalJson(output)),
  });
}

function outputKey(operationHmac) {
  return `${RETENTION_ROUTE_OUTPUT_PREFIX}${hex64(operationHmac, 'Retention route operation HMAC')}`;
}

function unsigned(value) {
  const { record_hmac_sha256: ignored, ...record } = value;
  return record;
}

function signOutput(value, secret) {
  const record = unsigned(value);
  return {
    ...record,
    record_hmac_sha256: hmacHex(secret, `${OUTPUT_SIGNATURE_DOMAIN}\n${canonicalJson(record)}`),
  };
}

export function validateRetentionRouteOutputMarker(value, expected, env = process.env) {
  const secret = env[RETENTION_GENERATION_FENCE_SECRET_ENV];
  if (!exactKeys(value, OUTPUT_FIELDS) || value.schema !== RETENTION_ROUTE_OUTPUT_SCHEMA ||
      value.version !== 1 || value.customer_data_stored !== false ||
      !Number.isSafeInteger(value.generation) || value.generation < 0 ||
      !Number.isSafeInteger(value.response_status) || value.response_status < 100 ||
      value.response_status > 599 || !ROUTE.test(value.route || '') ||
      !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(value.method)) {
    throw new TypeError('Retention route output marker is invalid.');
  }
  for (const field of ['operation_hmac_sha256', 'output_record_sha256', 'path_sha256',
    'request_sha256', 'response_body_sha256', 'idempotency_key_sha256', 'record_hmac_sha256']) {
    hex64(value[field], `Retention route output ${field}`);
  }
  const timestamp = Date.parse(value.completed_at);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value.completed_at) {
    throw new TypeError('Retention route output timestamp is invalid.');
  }
  const signature = hmacHex(secret, `${OUTPUT_SIGNATURE_DOMAIN}\n${canonicalJson(unsigned(value))}`);
  if (!safeEqual(signature, value.record_hmac_sha256)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_ROUTE_OUTPUT_SIGNATURE_INVALID');
  }
  for (const [field, expectedValue] of Object.entries(expected || {})) {
    if (value[field] !== expectedValue) {
      throw new Error('ARC_FIRST_PARTY_RETENTION_ROUTE_OUTPUT_BINDING_INVALID');
    }
  }
  return value;
}

async function strongEntry(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json', consistency: 'strong' });
  return entry ? { value: entry.data, etag: entry.etag } : null;
}

async function ensureOutputMarker(store, marker, env) {
  const key = outputKey(marker.operation_hmac_sha256);
  try { await store.setJSON(key, marker, { onlyIfNew: true }); } catch {}
  const stored = await strongEntry(store, key);
  if (!stored || canonicalJson(validateRetentionRouteOutputMarker(stored.value, {
    generation: marker.generation,
    operation_hmac_sha256: marker.operation_hmac_sha256,
    output_record_sha256: marker.output_record_sha256,
    request_sha256: marker.request_sha256,
    route: marker.route,
  }, env)) !== canonicalJson(marker)) {
    throw new Error('ARC_FIRST_PARTY_RETENTION_ROUTE_OUTPUT_CONFLICT');
  }
  return stored.value;
}

class HandlerResponseError extends Error {
  constructor(response) {
    super('ARC_FIRST_PARTY_RETENTION_ROUTE_HANDLER_5XX');
    this.response = response;
  }
}

function normalizeRouteOptions(options) {
  if (!options || typeof options.handler !== 'function' || typeof options.active !== 'function' ||
      typeof options.route !== 'string' || !ROUTE.test(options.route)) {
    throw new TypeError('Retention-fenced route options are invalid.');
  }
  const methods = options.methods === undefined ? ['POST'] : options.methods;
  const paths = options.paths === undefined ? null : options.paths;
  const maxRequestBytes = options.maxRequestBytes === undefined
    ? MAX_REQUEST_BYTES : options.maxRequestBytes;
  if (methods !== null && (!Array.isArray(methods) || methods.length === 0 ||
      methods.some((method) => typeof method !== 'string'))) {
    throw new TypeError('Retention-fenced route methods are invalid.');
  }
  if (paths !== null && (!Array.isArray(paths) || paths.length === 0 ||
      paths.some((path) => typeof path !== 'string' || !path.startsWith('/')))) {
    throw new TypeError('Retention-fenced route paths are invalid.');
  }
  if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 1 ||
      maxRequestBytes > MAX_REQUEST_BYTES) {
    throw new TypeError('Retention-fenced route body limit is invalid.');
  }
  return Object.freeze({
    ...options,
    methods: methods === null ? null : Object.freeze(methods.map((method) => method.toUpperCase())),
    maxRequestBytes,
    paths: paths === null ? null : Object.freeze([...paths]),
  });
}

function routeApplies(options, request, context, env) {
  if (options.methods && !options.methods.includes(String(request?.method || '').toUpperCase())) return false;
  if (options.paths && !options.paths.includes(requestPath(request))) return false;
  return options.active({ request, context, env }) === true;
}

function enqueueRouteFenceAlert(alert, env, context) {
  // Resolve an injected alert store only on a genuinely stale path. Inactive
  // routes and ordinary lock contention must not open the operations queue.
  const store = context.retentionFenceAlertStore || context.operationsAlertStore;
  return enqueueRetentionGenerationFenceCriticalAlert(alert, env, {
    clock: context.retentionFenceClock || context.clock,
    ...(store ? { store } : {}),
  });
}

export function createRetentionFencedRouteHandler(rawOptions) {
  const options = normalizeRouteOptions(rawOptions);
  return async (request, context = {}) => {
    const env = process.env;
    let active;
    try { active = routeApplies(options, request, context, env); }
    catch { return json(503, { error: 'retention_generation_fence_unavailable' }); }
    if (!active) return options.handler(request, context);
    if (!retentionGenerationFenceConfiguration(env).ready) {
      return json(503, { error: 'retention_generation_fence_unavailable' });
    }
    let identity;
    try { identity = await readRequestIdentity(request, options.maxRequestBytes); }
    catch (error) {
      if (error instanceof RangeError) return json(413, { error: 'request_too_large' });
      return json(503, { error: 'retention_generation_fence_unavailable' });
    }
    const secret = env[RETENTION_GENERATION_FENCE_SECRET_ENV];
    let store;
    try {
      store = context.retentionFenceStore || getStore({
        name: RETENTION_GENERATION_FENCE_STORE,
        consistency: 'strong',
      });
    } catch {
      return json(503, { error: 'retention_generation_fence_unavailable' });
    }
    let observedFence;
    try {
      observedFence = await ensureRetentionGenerationFence(store, env, {
        clock: () => nowDate(context),
      });
    } catch {
      return json(503, { error: 'retention_generation_fence_unavailable' });
    }
    const observedGeneration = observedFence.record.generation;
    const descriptor = routeDescriptor(options.route, identity, observedGeneration, secret);
    let handlerResponse = null;
    let replayMarker = null;
    const clock = () => nowDate(context);
    try {
      const result = await runRetentionProducerOperation(store, descriptor, env, {
        clock,
        expectedGeneration: observedGeneration,
        staleAfterMs: context.retentionFenceStaleAfterMs,
        heartbeatIntervalMs: context.retentionFenceHeartbeatIntervalMs,
        emitCriticalAlert: (alert) => enqueueRouteFenceAlert(alert, env, context),
        readSource: async () => {
          const reread = await readRequestIdentity(request, options.maxRequestBytes);
          return reread.source_record_sha256;
        },
        readOutput: async ({ generation, operation_hmac_sha256: operation }) => {
          const stored = await strongEntry(store, outputKey(operation));
          if (!stored) return MISSING_OUTPUT_SHA256;
          replayMarker = validateRetentionRouteOutputMarker(stored.value, {
            generation,
            operation_hmac_sha256: operation,
            output_record_sha256: descriptor.output_record_sha256,
            request_sha256: identity.source_record_sha256,
            route: options.route,
          }, env);
          return replayMarker.output_record_sha256;
        },
        mutate: async ({ generation, operation_hmac_sha256: operation }) => {
          const response = await options.handler(request, context);
          if (!(response instanceof Response)) {
            throw new TypeError('Retention-fenced route handler response is invalid.');
          }
          handlerResponse = response;
          if (response.status >= 500) throw new HandlerResponseError(response);
          const marker = signOutput({
            schema: RETENTION_ROUTE_OUTPUT_SCHEMA,
            version: 1,
            route: options.route,
            method: identity.method,
            path_sha256: identity.path_sha256,
            request_sha256: identity.source_record_sha256,
            idempotency_key_sha256: identity.idempotency_key_sha256,
            operation_hmac_sha256: operation,
            generation,
            output_record_sha256: descriptor.output_record_sha256,
            response_status: response.status,
            response_body_sha256: await responseBodyDigest(response),
            completed_at: clock().toISOString(),
            customer_data_stored: false,
          }, secret);
          replayMarker = await ensureOutputMarker(store, marker, env);
        },
      });
      if (result.retryable) {
        return json(503, { error: 'retention_generation_fence_contention', retryable: true });
      }
      if (handlerResponse) return handlerResponse;
      if (!replayMarker) {
        const stored = await strongEntry(store, outputKey(result.operation_hmac_sha256));
        if (!stored) throw new Error('ARC_FIRST_PARTY_RETENTION_ROUTE_OUTPUT_MISSING');
        replayMarker = validateRetentionRouteOutputMarker(stored.value, {
          operation_hmac_sha256: result.operation_hmac_sha256,
          output_record_sha256: descriptor.output_record_sha256,
          request_sha256: identity.source_record_sha256,
          route: options.route,
        }, env);
      }
      // The marker intentionally stores only digests, never a customer-facing
      // response body, cookie, bearer, checkout URL, or other replayable
      // secret. If a worker crashed after committing that marker but before
      // the fence receipt/reopen, the exact retry can safely validate and
      // finish the durable operation, but it cannot reconstruct the original
      // response. A retryable failure makes the caller enter the next OPEN
      // generation, where the route's domain idempotency can reproduce the
      // real response. Treating the digest-only marker as a generic success
      // would strand checkout, review-exchange, and claim callers without the
      // credential or URL they need.
      return json(503, { error: 'retention_route_response_unavailable', retryable: true });
    } catch (error) {
      if (error instanceof HandlerResponseError) return error.response;
      return json(503, { error: 'retention_generation_fence_unavailable' });
    }
  };
}

export async function writeRetentionLegalHoldFenced(input, env = process.env, adapters = {}) {
  if (!adapters.store) throw new TypeError('Retention legal-hold fence store is required.');
  const output = buildFirstPartyLegalHoldRecord(input, env);
  const key = firstPartyLegalHoldKey(input.family, input.subject_hmac_sha256);
  const outputSha = sha256Hex(canonicalJson(output));
  // The signed desired record is the deterministic request authority. Do not
  // bind operation identity to a hold read performed before WRITING: another
  // legal-hold producer could legitimately win and advance the generation in
  // that gap, leaving the stale-source operation unable to resume. The current
  // hold is read and CAS-replaced only after this operation owns WRITING.
  const sourceSha = sha256Hex(canonicalJson({
    schema: LEGAL_HOLD_REQUEST_SOURCE_SCHEMA,
    key_sha256: sha256Hex(key),
    output_record_sha256: outputSha,
  }));
  const mutationSha = sha256Hex(canonicalJson({
    schema: LEGAL_HOLD_MUTATION_SCHEMA,
    key_sha256: sha256Hex(key),
    source_record_sha256: sourceSha,
    output_record_sha256: outputSha,
  }));
  const descriptor = {
    route: 'legal-hold/write',
    subject_hmac_sha256: input.subject_hmac_sha256,
    idempotency_key_sha256: mutationSha,
    source_record_sha256: sourceSha,
    mutation_sha256: mutationSha,
    output_record_sha256: outputSha,
  };
  return runRetentionProducerOperation(adapters.store, descriptor, env, {
    clock: adapters.clock,
    staleAfterMs: adapters.staleAfterMs,
    heartbeatIntervalMs: adapters.heartbeatIntervalMs,
    emitCriticalAlert: adapters.emitCriticalAlert,
    readSource: async () => sourceSha,
    readOutput: async () => {
      const current = await strongEntry(adapters.store, key);
      return current ? sha256Hex(canonicalJson(current.value)) : MISSING_OUTPUT_SHA256;
    },
    mutate: async () => {
      const current = await strongEntry(adapters.store, key);
      const options = current ? { onlyIfMatch: current.etag } : { onlyIfNew: true };
      let result;
      try {
        result = await adapters.store.setJSON(key, output, options);
      } catch (error) {
        const recovered = await strongEntry(adapters.store, key);
        if (!recovered || sha256Hex(canonicalJson(recovered.value)) !== outputSha) throw error;
        return;
      }
      if (!result?.modified) {
        const raced = await strongEntry(adapters.store, key);
        if (!raced || sha256Hex(canonicalJson(raced.value)) !== outputSha) {
          throw new Error('ARC_FIRST_PARTY_RETENTION_LEGAL_HOLD_CONTENTION');
        }
        return;
      }
      if (adapters.afterMutation) await adapters.afterMutation(output);
    },
  });
}

export const retentionFencedRouteContract = Object.freeze({
  idempotency_headers: IDEMPOTENCY_HEADERS,
  max_request_bytes: MAX_REQUEST_BYTES,
  output_prefix: RETENTION_ROUTE_OUTPUT_PREFIX,
  output_schema: RETENTION_ROUTE_OUTPUT_SCHEMA,
});
