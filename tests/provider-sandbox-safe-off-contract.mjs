import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

import { RESEND_FROM_IDENTITY } from '../netlify/lib/resend-transactional-provider-core.mjs';
import { ARC_STRIPE_API_VERSION } from '../netlify/lib/stripe-api-version.mjs';
import {
  PROVIDER_SAFE_OFF_FLAG_NAMES,
  PROVIDER_SANDBOX_SAFE_OFF_CONTRACT as contract,
  createProviderSandboxSafeOffContractReport,
  createProviderSandboxSafeOffReport,
  runProviderSandboxSafeOffPreflightCli,
} from '../scripts/provider-sandbox-safe-off-preflight.mjs';

const clone = (value) => structuredClone(value);
const contractReport = createProviderSandboxSafeOffContractReport(contract);
assert.equal(contractReport.ok, true, JSON.stringify(contractReport));
assert.equal(contractReport.state, 'CONTRACT_VALID');
const report = createProviderSandboxSafeOffReport({});
assert.equal(report.ok, true, JSON.stringify(report));
assert.equal(report.state, 'SAFE_OFF_STAGED');
assert.equal(report.launch_ready, false);
assert.equal(report.checks.all_controls_off, true);
assert.equal(report.checks.sandbox_catalog_bound, true);
assert.equal(report.checks.restricted_key_evidence_bound, true);
assert.equal(report.checks.restricted_key_runtime_scope_match, false);
assert.equal(report.checks.stripe_api_version_bound, true);
assert.equal(report.checks.resend_provider_staged, true);
assert.equal(report.checks.sender_staged, true);
assert.equal(report.checks.secret_material_absent, true);
assert.equal(report.checks.actual_environment_controls_off, true);
assert.equal(report.checks.actual_stripe_api_version_compatible, true);
assert.equal(report.checks.actual_resend_sender_compatible, true);
assert.equal(contract.non_secret_environment.ARC_STRIPE_WEBHOOK_API_VERSION,
  ARC_STRIPE_API_VERSION);
assert.ok(report.blocked.includes('STRIPE_RESTRICTED_KEY_RUNTIME_SCOPE_MISMATCH'));
assert.ok(report.blocked.includes('STRIPE_WEBHOOK_NOT_CREATED'));
assert.ok(report.blocked.includes('PROVIDER_E2E_NOT_RUN'));

const enabled = clone(contract);
enabled.safe_off_environment.ARC_RESEND_SEND_ENABLED = 'true';
assert.ok(createProviderSandboxSafeOffContractReport(enabled).invalid.includes('SAFE_OFF_ENVIRONMENT'));

const wrongCatalog = clone(contract);
wrongCatalog.stripe.catalog.price_id = 'price_wrongSandboxCatalog';
assert.ok(createProviderSandboxSafeOffContractReport(wrongCatalog).invalid.includes('STRIPE_SANDBOX_BINDING'));

const broadKey = clone(contract);
broadKey.stripe.restricted_keys[0].required_prefix = 'sk_test_';
assert.ok(createProviderSandboxSafeOffContractReport(broadKey).invalid.includes(
  'STRIPE_RESTRICTED_KEY_CAPABILITIES'));

const wrongSender = clone(contract);
wrongSender.resend.sender_identity.value = 'ARC <preview@arcweb.onl>';
assert.ok(createProviderSandboxSafeOffContractReport(wrongSender).invalid.includes('RESEND_PROVIDER_BINDING'));

const incompleteWebhook = clone(contract);
incompleteWebhook.resend.webhook.required_events.pop();
assert.ok(createProviderSandboxSafeOffContractReport(incompleteWebhook).invalid.includes('RESEND_PROVIDER_BINDING'));

const incompleteSubscription = clone(contract);
incompleteSubscription.resend.webhook.subscribed_events.pop();
assert.ok(createProviderSandboxSafeOffContractReport(incompleteSubscription).invalid.includes(
  'RESEND_PROVIDER_BINDING'));

const leaked = clone(contract);
leaked.resend.api_key.unexpected = 're_thisWouldBeSecretMaterial0123456789';
const leakReport = createProviderSandboxSafeOffContractReport(leaked);
assert.ok(leakReport.invalid.includes('SECRET_MATERIAL_FORBIDDEN'));
assert.equal(JSON.stringify(leakReport).includes('thisWouldBeSecretMaterial'), false,
  'Preflight output must never echo secret material.');

const staleVersion = clone(contract);
staleVersion.non_secret_environment.ARC_STRIPE_WEBHOOK_API_VERSION = '2026-07-29.dahlia';
assert.ok(createProviderSandboxSafeOffContractReport(staleVersion).invalid.includes(
  'STRIPE_API_VERSION_BINDING'));

for (const name of PROVIDER_SAFE_OFF_FLAG_NAMES) {
  const enabledReport = createProviderSandboxSafeOffReport({ [name]: 'true' });
  assert.equal(enabledReport.ok, false, `${name}=true must fail SAFE_OFF.`);
  assert.ok(enabledReport.invalid.includes('RUNTIME_SAFE_OFF_ENVIRONMENT'));
  assert.deepEqual(enabledReport.enabled_flags, [name]);
  assert.equal(createProviderSandboxSafeOffReport({ [name]: 'false' }).ok, true,
    `${name}=false must remain SAFE_OFF.`);
}
for (const malformed of ['', '0', 'FALSE', false]) {
  const malformedReport = createProviderSandboxSafeOffReport({
    ARC_RESEND_SEND_ENABLED: malformed,
  });
  assert.ok(malformedReport.invalid.includes('RUNTIME_SAFE_OFF_ENVIRONMENT'));
}
assert.ok(createProviderSandboxSafeOffReport({
  ARC_FUTURE_PROVIDER_ENABLED: 'true',
}).invalid.includes('RUNTIME_SAFE_OFF_ENVIRONMENT'),
'A newly supplied ARC *_ENABLED flag must fail closed before the static inventory is updated.');
assert.equal(createProviderSandboxSafeOffReport({
  ARC_STRIPE_WEBHOOK_API_VERSION: ARC_STRIPE_API_VERSION,
}).ok, true);
for (const unsupported of ['2026-07-29.dahlia', '2026-07-29.preview', '']) {
  assert.ok(createProviderSandboxSafeOffReport({
    ARC_STRIPE_WEBHOOK_API_VERSION: unsupported,
  }).invalid.includes('RUNTIME_STRIPE_API_VERSION_BINDING'));
}
assert.equal(createProviderSandboxSafeOffReport({ ARC_RESEND_FROM: RESEND_FROM_IDENTITY }).ok, true);
for (const unsupportedSender of [
  'ARC Web <preview@send.arcweb.onl>',
  'ARC <previews@send.arcweb.onl>',
  'preview@send.arcweb.onl',
  'ARC <preview@arcweb.onl>',
]) {
  assert.ok(createProviderSandboxSafeOffReport({ ARC_RESEND_FROM: unsupportedSender })
    .invalid.includes('RUNTIME_RESEND_SENDER_IDENTITY'));
}

let cliOutput = '';
assert.equal(runProviderSandboxSafeOffPreflightCli({
  argv: [], env: {}, write: (value) => { cliOutput += value; },
}), 0);
const cliReport = JSON.parse(cliOutput);
assert.equal(cliReport.state, 'SAFE_OFF_STAGED');
assert.equal(runProviderSandboxSafeOffPreflightCli({ argv: ['--enable'] }), 2);
let rejectedOutput = '';
assert.equal(runProviderSandboxSafeOffPreflightCli({
  argv: [],
  env: { ARC_RESEND_SEND_ENABLED: 'true' },
  write: (value) => { rejectedOutput += value; },
}), 1);
assert.ok(JSON.parse(rejectedOutput).invalid.includes('RUNTIME_SAFE_OFF_ENVIRONMENT'));

const cliUrl = new URL('../scripts/provider-sandbox-safe-off-preflight.mjs', import.meta.url);
const processFailure = spawnSync(process.execPath, [cliUrl.pathname], {
  encoding: 'utf8',
  env: { ARC_RESEND_SEND_ENABLED: 'true' },
});
assert.equal(processFailure.status, 1,
  'The executable preflight must return nonzero from its actual process.env.');
assert.ok(JSON.parse(processFailure.stdout).invalid.includes('RUNTIME_SAFE_OFF_ENVIRONMENT'));
