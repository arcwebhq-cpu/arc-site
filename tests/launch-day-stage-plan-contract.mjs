import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const plan = JSON.parse(await readFile(
  new URL('../operations/launch-day-stage-plan.json', import.meta.url),
  'utf8',
));

assert.equal(plan.schema, 'arc-launch-day-stage-plan-v1');
assert.equal(plan.version, 1);
assert.equal(plan.state, 'SAFE_OFF');
assert.equal(plan.activation_allowed, false);
assert.equal(plan.automatic_activation, false);
assert.equal(plan.site.branch, 'codex/arc-v11-site-final-pair-20260830');
assert.equal(plan.site.netlify_site_id, 'e2b737ab-70e1-48d2-9d99-a6718c04fa86');
assert.equal(plan.previews.remote_commit_sha, '795df3e6352ffe1725dcec876259c63933aa2e7a');
assert.equal(plan.previews.pin_state, 'VERIFIED_REMOTE_SHA');
assert.match(plan.previews.pin_rule, /exact 40-character commit SHA.*independently read back/i);
assert.deepEqual(plan.stages.map(({ name }) => name), [
  'SAFE_OFF', 'EMAIL_SANDBOX', 'CLAIM_SANDBOX', 'LIVE_CHECKOUT',
  'PUBLIC_INTAKE', 'PILOT', 'OUTREACH',
]);
assert.equal(plan.stages[0].state, 'VERIFIED');
assert.ok(plan.stages.every(({ mutation_allowed }) => mutation_allowed === false));
assert.ok(plan.stages.slice(1).every(({ state }) => state === 'BLOCKED'));
for (const blocker of [
  'STRIPE_WEBHOOK_NOT_CREATED',
  'STRIPE_WORKBENCH_SUPPORTED_ROLE_REQUIRED',
  'NETLIFY_DEPLOY_CREDITS_PAUSED_UNTIL_2026-09-16',
  'PROVIDER_E2E_NOT_RUN',
  'ZAPIER_REVERSAL_SOURCE_VALIDATION_PENDING',
]) assert.ok(plan.blockers.includes(blocker));
assert.deepEqual(plan.launch_rules, {
  one_stage_at_a_time: true,
  signed_evidence_required: true,
  provider_readback_required: true,
  rollback_to_safe_off_on_any_failure: true,
  charges_emails_intake_and_outreach_remain_disabled: true,
});

console.log('ARC launch-day stage plan contract passed.');
