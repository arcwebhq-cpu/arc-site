import { getStore } from '@netlify/blobs';
import {
  authenticateBearer,
  canonicalJson,
  hmacHex,
  jsonResponse,
  parseJsonBodyText,
  sha256Hex,
} from '../lib/arc2-handoff-core.mjs';
import { INTAKE_STORE } from '../lib/intake-submission-core.mjs';
import { readBoundedRequestText, RequestBodyTooLargeError } from '../lib/bounded-request-body.mjs';
import {
  RETENTION_CONTROL_STORE,
  preflightRetentionManifest,
  retentionConfiguration,
  retentionKeys,
  runRetentionManifest,
} from '../lib/retention-control-core.mjs';
import {
  assertRetentionGenerationFenceAuthority,
  beginRetentionFreeze,
  completeRetentionFreeze,
  ensureRetentionGenerationFence,
  recordRetentionMissingSourceAnomaly,
  renewRetentionGenerationFenceAuthority,
  retentionFreezeOperationHmac,
} from '../lib/retention-generation-fence-core.mjs';
import { enqueueRetentionGenerationFenceCriticalAlert } from
  '../lib/retention-generation-fence-alert-queue-core.mjs';

const FENCE_SECRET_ENV = 'ARC_FIRST_PARTY_RETENTION_FENCE_HMAC_SECRET';

function retentionFreezeDescriptor(preflight, generation, env) {
  return Object.freeze({
    generation,
    manifest_entry_count: preflight.target_count,
    manifest_sha256: preflight.manifest_sha256,
    subject_hmac_sha256: hmacHex(env[FENCE_SECRET_ENV],
      `arc-legacy-retention-manifest-subject-v1\n${preflight.target_set_sha256}`),
  });
}

async function readLegacyRetentionOutput(stores, manifest, preflight, env) {
  const completion = await stores.control.getWithMetadata(
    retentionKeys.completionKey(preflight.run_id), { type: 'json', consistency: 'strong' },
  );
  if (!completion || completion.data?.manifest_sha256 !== preflight.manifest_sha256 ||
      completion.data?.target_count !== preflight.target_count || completion.data?.missing !== 0) {
    throw new Error('ARC_RETENTION_COMPLETION_READBACK_INVALID');
  }
  const outputs = [];
  for (const target of manifest.targets) {
    const entry = await stores.intake.getWithMetadata(target.key, {
      type: 'json', consistency: 'strong',
    });
    if (!entry) throw new Error('ARC_RETENTION_TARGET_MISSING_DURING_FINAL_READBACK');
    outputs.push({ key_hmac_sha256: hmacHex(env[FENCE_SECRET_ENV],
      `arc-legacy-retention-output-key-v1\n${target.store}\n${target.key}`),
    record_sha256: sha256Hex(canonicalJson(entry.data)) });
  }
  return Object.freeze({
    completion: completion.data,
    outputs,
    output_readback_sha256: sha256Hex(canonicalJson({ completion: completion.data, outputs })),
    primary_output_sha256: outputs[0].record_sha256,
    output_set_sha256: sha256Hex(canonicalJson(outputs)),
  });
}

const resultResponse = (result) => jsonResponse(200, {
  run_id: result.run_id,
  mode: result.mode,
  target_count: result.target_count,
  eligible: result.eligible,
  deleted: result.deleted,
  legal_hold: result.legal_hold,
  missing: result.missing,
  not_expired: result.not_expired,
  resumed: result.resumed,
  idempotent_replay: result.idempotent_replay,
  provider_cleanup_included: false,
});

export default async (request, context = {}) => {
  const configuration = retentionConfiguration(process.env);
  if (!configuration.enabled) return jsonResponse(503, { error: 'retention_cleanup_disabled' });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'method_not_allowed' });
  if (!authenticateBearer(request, process.env.ARC_RETENTION_CLEANUP_SECRET)) return jsonResponse(401, { error: 'unauthorized' });
  if ((request.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return jsonResponse(415, { error: 'json_required' });
  }
  try {
    const body = parseJsonBodyText(await readBoundedRequestText(request, 250_000), 250_000);
    if (Object.keys(body).length !== 2 || typeof body.manifest !== 'string' || typeof body.manifest_hmac_sha256 !== 'string') {
      return jsonResponse(400, { error: 'invalid_retention_manifest' });
    }
    const stores = {
      control: context.retentionStore || getStore({ name: RETENTION_CONTROL_STORE, consistency: 'strong' }),
      intake: context.intakeStore || getStore({ name: INTAKE_STORE, consistency: 'strong' }),
    };
    const emitCriticalAlert = context.emitCriticalAlert || ((alert) => {
      const alertStore = context.retentionFenceAlertStore || context.operationsAlertStore;
      return enqueueRetentionGenerationFenceCriticalAlert(alert, process.env, {
        clock: context.clock,
        ...(alertStore ? { store: alertStore } : {}),
      });
    });
    // The signed manifest is completely validated before taking the global
    // retention freeze. Invalid requests must never strand the gate.
    const preflight = await preflightRetentionManifest(
      body.manifest, body.manifest_hmac_sha256, process.env, stores, { clock: context.clock },
    );
    if (preflight.target_count !== 1) {
      return jsonResponse(400, { error: 'single_subject_retention_manifest_required' });
    }
    const manifest = JSON.parse(body.manifest);
    const observed = await ensureRetentionGenerationFence(stores.control, process.env,
      { clock: context.clock });
    const descriptor = retentionFreezeDescriptor(preflight, observed.record.generation, process.env);
    const expectedOperation = retentionFreezeOperationHmac(descriptor, process.env);
    const priorCompletion = await stores.control.getWithMetadata(
      retentionKeys.completionKey(preflight.run_id), { type: 'json', consistency: 'strong' },
    );
    const resumingExactFreeze = observed.record.status === 'FROZEN' &&
      observed.record.operation_hmac_sha256 === expectedOperation;
    if (priorCompletion?.data?.manifest_sha256 === preflight.manifest_sha256 &&
        priorCompletion.data.missing === 0 && !resumingExactFreeze) {
      // A completed legacy run is immutable. Validate its durable outputs and
      // answer a true read-only replay instead of allocating a new generation.
      const replay = await runRetentionManifest(
        body.manifest, body.manifest_hmac_sha256, process.env, stores, { clock: context.clock },
      );
      await readLegacyRetentionOutput(stores, manifest, preflight, process.env);
      return resultResponse(replay);
    }
    const begun = await beginRetentionFreeze(stores.control, descriptor, process.env,
      { clock: context.clock, emitCriticalAlert });
    if (begun.retryable) return jsonResponse(409, { error: 'retention_contention' });

    // A fully finalized exact replay is read-only; its immutable legacy
    // completion remains the response authority.
    if (begun.state === 'COMPLETE') {
      const result = await runRetentionManifest(
        body.manifest, body.manifest_hmac_sha256, process.env, stores, { clock: context.clock },
      );
      return resultResponse(result);
    }

    let authority = Object.freeze({
      status: 'FROZEN',
      generation: begun.generation,
      operation_hmac_sha256: begun.operation_hmac_sha256,
      intent_sha256: begun.intent_sha256,
      authority_etag: begun.authority_etag,
    });
    const assertAuthority = async () => {
      await assertRetentionGenerationFenceAuthority(stores.control, authority, process.env);
    };
    const renewAuthority = async () => {
      authority = await renewRetentionGenerationFenceAuthority(
        stores.control, authority, process.env,
        { clock: context.clock, emitCriticalAlert },
      );
    };
    const onMissingSource = async (missing) => {
      await assertAuthority();
      await recordRetentionMissingSourceAnomaly(stores.control, descriptor, {
        family: 'legacy_intake',
        source_key_hmac_sha256: hmacHex(process.env[FENCE_SECRET_ENV],
          `arc-legacy-retention-missing-source-v1\n${missing.source_store}\n${missing.source_key}`),
        expected_source_record_sha256: missing.expected_source_record_sha256,
      }, process.env, { clock: context.clock, authorityEtag: authority.authority_etag });
    };
    const result = await runRetentionManifest(
      body.manifest, body.manifest_hmac_sha256, process.env, stores,
      { assertAuthority, clock: context.clock, onMissingSource, renewAuthority },
    );
    await assertAuthority();
    const output = await readLegacyRetentionOutput(stores, manifest, preflight, process.env);
    await assertAuthority();
    const nonDestructiveDryRunEvidence = result.mode === 'dry-run' ? sha256Hex(canonicalJson({
      destructive_action_completed: false,
      manifest_sha256: preflight.manifest_sha256,
      mode: 'dry-run',
      output_readback_sha256: output.output_readback_sha256,
    })) : null;
    const evidence = Object.freeze({
      legal_hold_recheck_sha256: sha256Hex(canonicalJson({
        legal_hold: result.legal_hold,
        manifest_sha256: preflight.manifest_sha256,
      })),
      output_readback_sha256: output.output_readback_sha256,
      primary_tombstone_sha256: nonDestructiveDryRunEvidence || output.primary_output_sha256,
      tombstone_set_sha256: nonDestructiveDryRunEvidence || output.output_set_sha256,
    });
    const completed = await completeRetentionFreeze(
      stores.control, descriptor, evidence, process.env, {
        authorityEtag: authority.authority_etag,
        clock: context.clock,
        readback: async () => {
          await assertAuthority();
          return (await readLegacyRetentionOutput(
            stores, manifest, preflight, process.env,
          )).output_readback_sha256;
        },
      },
    );
    if (completed.retryable) return jsonResponse(409, { error: 'retention_contention' });
    return resultResponse(result);
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return jsonResponse(413, { error: 'retention_manifest_too_large' });
    if (error instanceof TypeError || error?.name === 'SyntaxError') return jsonResponse(400, { error: 'invalid_retention_manifest' });
    if (/DISABLED/.test(error?.message || '')) return jsonResponse(503, { error: 'retention_cleanup_disabled' });
    if (/MISSING/.test(error?.message || '')) return jsonResponse(409, { error: 'retention_missing_source' });
    if (/CONFLICT|CHANGED|ORDER|CONTENTION|DRIFT|AUTHORITY_LOST/.test(error?.message || '')) {
      return jsonResponse(409, { error: 'retention_conflict' });
    }
    return jsonResponse(503, { error: 'retention_cleanup_unavailable' });
  }
};

export const config = {
  path: '/internal/retention/cleanup',
  method: 'POST',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
