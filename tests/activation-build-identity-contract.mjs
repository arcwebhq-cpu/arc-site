import assert from 'node:assert/strict';
import {
  activationBuildIdentity,
  activationBuildIdentityModule,
} from '../scripts/activation-build-identity.mjs';
import { ACTIVATION_BUILD_IDENTITY } from '../netlify/lib/activation-build-identity.mjs';

const sha = '9'.repeat(40);
assert.deepEqual(activationBuildIdentity(undefined), {
  schema: 'arc-activation-build-identity-v1',
  version: 1,
  deployment_sha: null,
});
assert.deepEqual(activationBuildIdentity(sha), {
  schema: 'arc-activation-build-identity-v1',
  version: 1,
  deployment_sha: sha,
});
assert.throws(() => activationBuildIdentity('ABC'), /40 lowercase hexadecimal/);
assert.match(activationBuildIdentityModule(sha), new RegExp(sha));
assert.equal(ACTIVATION_BUILD_IDENTITY.deployment_sha, sha,
  'the test build must embed its identity before runtime modules load');

console.log('Activation build identity contract passed.');
