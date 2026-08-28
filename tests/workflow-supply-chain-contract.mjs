import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = await readFile(path.join(root, ".github/workflows/arc-site-quality.yml"), "utf8");
const dependabot = await readFile(path.join(root, ".github/dependabot.yml"), "utf8");
const productionRouteVerifier = await readFile(path.join(root, "scripts/verify-production-routes.mjs"), "utf8");
const productionRouteRetry = await readFile(path.join(root, "scripts/lib/verify-production-route-retry.mjs"), "utf8");
const reviewed = new Map([
  ["actions/checkout", { sha: "3d3c42e5aac5ba805825da76410c181273ba90b1", version: "v7.0.1", count: 3 }],
  ["actions/setup-node", { sha: "820762786026740c76f36085b0efc47a31fe5020", version: "v7.0.0", count: 2 }]
]);
const uses = [...workflow.matchAll(/^[ \t]*-?[ \t]*uses:[ \t]+([^ \t#]+)(?:[ \t]+#[ \t]*(\S+))?[ \t]*$/gm)]
  .map(match => ({ action: match[1].split("@")[0], ref: match[1].split("@")[1], version: match[2] }));

assert.match(workflow, /repository:\s*arcwebhq-cpu\/arc-previews\s*\n\s*ref:\s*74810e3cc7ef03b6d1d002a418314dd158dce6a2\s*\n\s*path:\s*\.arc-previews-contract/,
  "ARC site CI must pin the reviewed five-page preview contract commit");

assert.equal(uses.length, 5);
for (const use of uses) {
  assert.match(use.ref ?? "", /^[a-f0-9]{40}$/);
  const expected = reviewed.get(use.action);
  assert.ok(expected, `unreviewed action introduced: ${use.action}`);
  assert.equal(use.ref, expected.sha);
  assert.equal(use.version, expected.version);
}
for (const [action, expected] of reviewed) {
  assert.equal(uses.filter(use => use.action === action).length, expected.count);
}

assert.match(dependabot, /^version:\s*2\s*$/m);
for (const ecosystem of ["github-actions", "npm"]) {
  assert.match(dependabot, new RegExp(`package-ecosystem:\\s*${ecosystem}[\\s\\S]*?directory:\\s*["']\\/["'][\\s\\S]*?interval:\\s*weekly`));
}
assert.match(productionRouteVerifier, /await Promise\.all\(\[/,
  "Production route checks must share one bounded propagation window instead of serial cold starts.");
assert.match(productionRouteVerifier, /fetchAndVerifyWithRetries/);
assert.match(productionRouteRetry, /deadlineMs = 60_000/);
assert.match(productionRouteRetry, /requestTimeoutMs = 15_000/);
assert.match(productionRouteRetry, /new Set\(\[404, 408, 425, 429, 500, 502, 503, 504\]\)/);
assert.match(productionRouteRetry, /if \(isUnexpectedRedirect\(error\)\) throw error/);
assert.match(productionRouteRetry, /if \(!TRANSIENT_ROUTE_STATUSES\.has\(response\?\.status\)\) throw error/,
  "Successful responses with unsafe content and redirect regressions must fail immediately.");
console.log("ARC site workflow supply-chain contract passed.");
