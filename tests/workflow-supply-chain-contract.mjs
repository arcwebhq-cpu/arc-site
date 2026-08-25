import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = await readFile(path.join(root, ".github/workflows/arc-site-quality.yml"), "utf8");
const dependabot = await readFile(path.join(root, ".github/dependabot.yml"), "utf8");
const reviewed = new Map([
  ["actions/checkout", { sha: "3d3c42e5aac5ba805825da76410c181273ba90b1", version: "v7.0.1", count: 3 }],
  ["actions/setup-node", { sha: "820762786026740c76f36085b0efc47a31fe5020", version: "v7.0.0", count: 2 }]
]);
const uses = [...workflow.matchAll(/^[ \t]*-?[ \t]*uses:[ \t]+([^ \t#]+)(?:[ \t]+#[ \t]*(\S+))?[ \t]*$/gm)]
  .map(match => ({ action: match[1].split("@")[0], ref: match[1].split("@")[1], version: match[2] }));

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
console.log("ARC site workflow supply-chain contract passed.");
