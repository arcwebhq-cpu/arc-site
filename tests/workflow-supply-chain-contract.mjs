import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = await readFile(path.join(root, ".github/workflows/arc-site-quality.yml"), "utf8");
const dependabot = await readFile(path.join(root, ".github/dependabot.yml"), "utf8");
const reviewed = new Map([
  ["actions/checkout", { sha: "11d5960a326750d5838078e36cf38b85af677262", version: "v4.4.0", count: 2 }],
  ["actions/setup-node", { sha: "49933ea5288caeca8642d1e84afbd3f7d6820020", version: "v4.4.0", count: 1 }]
]);
const uses = [...workflow.matchAll(/^[ \t]*-?[ \t]*uses:[ \t]+([^ \t#]+)(?:[ \t]+#[ \t]*(\S+))?[ \t]*$/gm)]
  .map(match => ({ action: match[1].split("@")[0], ref: match[1].split("@")[1], version: match[2] }));

assert.equal(uses.length, 3);
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
