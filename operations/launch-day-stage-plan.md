# ARC launch-day runbook

This plan is intentionally `SAFE_OFF`. It does not authorize a merge, deploy,
provider mutation, payment, email, public intake, pilot, or outreach action.

## Before September 16

1. Keep all 64 controls in `operations/arc2-sandbox-netlify-environment.json`
   exactly `false`.
2. Publish and independently read back both reviewed branches.
3. Preserve the independently read-back preview pin
   `795df3e6352ffe1725dcec876259c63933aa2e7a`. Never guess, shorten, or locally
   infer a replacement pin.
4. Validate the paused Zapier source against the site contracts. Reversal
   binding and recheck producers must persist and retry the byte-identical
   canonical signed evidence body.
5. Create the Stripe test webhook only with the supported Workbench role, then
   run sandbox provider E2E. Keep live-mode keys and charges out of this stage.

## September 16 launch sequence

1. Confirm Netlify deploy credits are available and the dedicated sandbox site
   still has ID `e2b737ab-70e1-48d2-9d99-a6718c04fa86`.
2. Re-run the complete site and preview suites, secret scan, immutable cross-repo
   pin check, and provider readbacks on the exact remote commits.
3. Deploy the `SAFE_OFF` build first. Confirm public intake returns the disabled
   response and no email, payment, worker, or automation can run.
4. Advance one signed activation stage at a time: email sandbox, claim sandbox,
   live Checkout, public intake, pilot, then outreach. Re-run the stage-specific
   evidence and readback before every transition.
5. On any mismatch, stale evidence, missing readback, or provider error, stop and
   restore the exact 64-control `SAFE_OFF` environment. Do not skip a stage.

The final four stages require explicit launch-day authority. Nothing in this
runbook schedules or performs activation automatically.
