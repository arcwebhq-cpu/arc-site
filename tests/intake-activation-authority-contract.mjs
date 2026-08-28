import assert from 'node:assert/strict';

import { createIntakeArc1AdapterBackgroundHandler } from '../netlify/functions/intake-arc1-adapter-background.mjs';
import { createIntakeArc1AdapterClaimHandler } from '../netlify/functions/intake-arc1-adapter-claim.mjs';
import { createIntakeArc1AdapterCompletionHandler } from '../netlify/functions/intake-arc1-adapter-complete.mjs';
import { createIntakeArc1AdapterLegacyMigrationHandler } from '../netlify/functions/intake-arc1-adapter-legacy-migration.mjs';
import { createIntakeArc1AdapterRecoveryHandler } from '../netlify/functions/intake-arc1-adapter-recovery.mjs';
import { createIntakeArc1AdapterHandler } from '../netlify/functions/intake-arc1-adapter.mjs';
import { createIntakeArc1BackgroundHandler } from '../netlify/functions/intake-arc1-background.mjs';
import { createIntakeArc1BridgeHandler } from '../netlify/functions/intake-arc1-bridge.mjs';
import { createIntakeArc1RecoveryHandler } from '../netlify/functions/intake-arc1-recovery.mjs';
import { createIntakePrivateAssetHandler } from '../netlify/functions/intake-private-asset.mjs';
import { createIntakeConfirmationClaimHandler } from '../netlify/functions/intake-confirmation-claim.mjs';
import { createIntakeConfirmationCompletionHandler } from '../netlify/functions/intake-confirmation-complete.mjs';
import {
  acceptArc1AdapterEnvelope,
  claimArc1AdapterConsumer,
  completeArc1AdapterConsumer,
  dispatchArc1AdapterRecord,
  markArc1AdapterQueueUnavailable,
  migrateLegacyArc1AdapterRecords,
  queueArc1AdapterDispatch,
  recoverPendingArc1AdapterDispatches,
} from '../netlify/lib/intake-arc1-adapter-core.mjs';
import { deliverIntakeToArc1 } from '../netlify/lib/intake-arc1-bridge-core.mjs';
import {
  dispatchIntakeToArc1Background,
  recoverPendingArc1Dispatches,
} from '../netlify/lib/intake-arc1-dispatch-core.mjs';
import { runArc1AdapterRecoveryCycle } from '../netlify/lib/intake-arc1-adapter-recovery-runner-core.mjs';
import { retrievePrivateAsset } from '../netlify/lib/intake-private-asset-core.mjs';
import {
  claimIntakeConfirmationOutbox,
  completeIntakeConfirmationOutbox,
  reserveIntakeConfirmationOutbox,
} from '../netlify/lib/intake-confirmation-outbox-core.mjs';
import { testActivationAuthority } from './helpers/activation-authority.mjs';

const now = new Date();
const request = () => new Request('https://arcweb.onl/internal/intake/arc1/authority-test', { method: 'POST' });
const enabledStack = {
  ARC_INTAKE_ARC1_ADAPTER_ENABLED: 'true',
  ARC_INTAKE_ARC1_BRIDGE_ENABLED: 'true',
  ARC_INTAKE_ARC1_DISPATCH_ENABLED: 'true',
  ARC_INTAKE_ARC1_DOWNSTREAM_ENABLED: 'true',
  ARC_INTAKE_ARC1_LEGACY_MIGRATION_ENABLED: 'true',
  ARC_INTAKE_ASSET_RETRIEVAL_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_CLAIM_ENABLED: 'true',
  ARC_INTAKE_ARC1_CONSUMER_COMPLETION_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_OUTBOX_ENABLED: 'true',
  ARC_INTAKE_CONFIRMATION_CONSUMER_ENABLED: 'true',
  ARC_INTAKE_ARC1_RUN_SECRET: 'authority-test-run-secret-0123456789abcdef',
  ARC_INTAKE_ARC1_DISPATCH_SECRET: 'authority-test-dispatch-secret-0123456789',
  ARC_INTAKE_ARC1_DESTINATION_BEARER: 'authority-test-destination-bearer-0123456789',
  ARC_INTAKE_ARC1_CONSUMER_BEARER: 'authority-test-consumer-bearer-0123456789',
};
const validAuthority = testActivationAuthority(now);
const insufficientAuthority = testActivationAuthority(now, { stage: 'LIVE_CHECKOUT' });
const expiredAuthority = testActivationAuthority(now, {
  issuedAt: new Date(now.getTime() - 2 * 60 * 60_000),
  expiresAt: new Date(now.getTime() - 60 * 60_000),
});
const missingAuthority = { ...validAuthority };
delete missingAuthority.ARC_ACTIVATION_MANIFEST;

const handlerFactories = [
  createIntakeArc1AdapterBackgroundHandler,
  createIntakeArc1AdapterClaimHandler,
  createIntakeArc1AdapterCompletionHandler,
  createIntakeArc1AdapterLegacyMigrationHandler,
  createIntakeArc1AdapterRecoveryHandler,
  createIntakeArc1AdapterHandler,
  createIntakeArc1BackgroundHandler,
  createIntakeArc1BridgeHandler,
  createIntakeArc1RecoveryHandler,
  createIntakePrivateAssetHandler,
  createIntakeConfirmationClaimHandler,
  createIntakeConfirmationCompletionHandler,
];
const authorityEnvNames = [...new Set([
  ...Object.keys(enabledStack),
  ...Object.keys(validAuthority),
])];
const saved = Object.fromEntries(authorityEnvNames.map((name) => [name, process.env[name]]));

function installAuthority(authority) {
  for (const name of authorityEnvNames) delete process.env[name];
  Object.assign(process.env, enabledStack, authority);
}

let handlerSideEffects = 0;
const guardedContext = new Proxy({}, {
  get() {
    handlerSideEffects += 1;
    throw new Error('Authority failure touched a handler dependency.');
  },
});

try {
  for (const authority of [missingAuthority, expiredAuthority, insufficientAuthority]) {
    installAuthority(authority);
    for (const factory of handlerFactories) {
      const response = await factory()(request(), guardedContext);
      assert.equal(response.status, 503, `${factory.name} must fail closed before auth, storage, or network.`);
      assert.deepEqual(await response.json(), { error: 'public_intake_authority_required' });
    }
  }
  assert.equal(handlerSideEffects, 0);

  installAuthority(validAuthority);
  for (const factory of handlerFactories) {
    const response = await factory()(request(), guardedContext);
    assert.equal(response.status, 401, `${factory.name} should reach authentication only with valid PUBLIC_INTAKE authority.`);
  }
  assert.equal(handlerSideEffects, 0);
} finally {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

let coreSideEffects = 0;
const noSideEffectStore = new Proxy({}, {
  get() {
    coreSideEffects += 1;
    throw new Error('Authority failure touched durable state.');
  },
});
const noNetwork = async () => {
  coreSideEffects += 1;
  throw new Error('Authority failure entered the network.');
};
const unauthorizedEnv = { ...enabledStack, ...missingAuthority };
const coreCalls = [
  () => deliverIntakeToArc1('invalid', unauthorizedEnv, { store: noSideEffectStore, fetch: noNetwork }),
  () => dispatchIntakeToArc1Background('invalid', request(), unauthorizedEnv, { store: noSideEffectStore, fetch: noNetwork }),
  () => recoverPendingArc1Dispatches(request(), unauthorizedEnv, { store: noSideEffectStore, fetch: noNetwork }),
  () => acceptArc1AdapterEnvelope('{}', request(), unauthorizedEnv,
    { source: noSideEffectStore, adapter: noSideEffectStore }, { fetch: noNetwork }),
  () => markArc1AdapterQueueUnavailable('invalid', unauthorizedEnv, noSideEffectStore),
  () => queueArc1AdapterDispatch('invalid', request(), unauthorizedEnv, { fetch: noNetwork }),
  () => claimArc1AdapterConsumer('{}', request(), unauthorizedEnv, noSideEffectStore),
  () => completeArc1AdapterConsumer('{}', request(), unauthorizedEnv, noSideEffectStore),
  () => dispatchArc1AdapterRecord('invalid', unauthorizedEnv,
    { source: noSideEffectStore, adapter: noSideEffectStore }, { fetch: noNetwork }),
  () => recoverPendingArc1AdapterDispatches(request(), unauthorizedEnv,
    { source: noSideEffectStore, adapter: noSideEffectStore }, { fetch: noNetwork }),
  () => migrateLegacyArc1AdapterRecords(request(), unauthorizedEnv, noSideEffectStore),
  () => retrievePrivateAsset({}, unauthorizedEnv, { store: noSideEffectStore }),
  () => reserveIntakeConfirmationOutbox({}, unauthorizedEnv, noSideEffectStore),
  () => claimIntakeConfirmationOutbox('{}', request(), unauthorizedEnv, noSideEffectStore),
  () => completeIntakeConfirmationOutbox('{}', request(), unauthorizedEnv, noSideEffectStore),
  () => runArc1AdapterRecoveryCycle(unauthorizedEnv, { source: noSideEffectStore, adapter: noSideEffectStore }),
];
for (const call of coreCalls) await assert.rejects(call, /ARC_PUBLIC_INTAKE_AUTHORITY_REQUIRED/);
assert.equal(coreSideEffects, 0, 'Missing authority must stop every core boundary before Blob or network access.');

console.log('ARC downstream intake activation authority boundary contract passed.');
