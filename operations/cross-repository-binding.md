# Cross-repository contract binding

ARC uses an asymmetric binding so two repositories never need to predict each other's future
commit SHA.

- `arc-site` checks out `arc-previews` at one reviewed, immutable commit SHA.
- `arc-previews` may check out `arc-site` from `main`, but a verifier owned by `arc-previews`
  recomputes and compares the exact partner-contract digest before installing dependencies or
  importing any site code.
- The digest covers every site path consumed by preview CI: the complete `netlify/lib` tree,
  `netlify/functions/arc2-handoff-start.mjs`, the imported review-activation environment contract,
  both npm manifests, and the complete local override package. Symlinks and unexpected files inside covered directories fail closed. Partner npm
  lifecycle scripts stay disabled.

Release order is directional:

1. For an `arc-site` partner-contract change, update this manifest and merge `arc-site`, then update
   the reviewed digest in `arc-previews`.
2. For an `arc-previews` contract change, merge `arc-previews`, then update the immutable preview
   commit in `arc-site`.
3. A binding-only update does not require a reverse pin. The content digest, not a mutually
   recursive pair of future commit SHAs, is the compatibility authority in the reverse direction.

Never execute or install from a mutable partner checkout before its locally trusted digest verifier
passes. Regenerate a digest only after reviewing every changed covered path.

After reviewing an ARC site contract change, regenerate deterministically with
`npm run update:partner-contract`. The command refuses dynamic imports, relative imports that leave
the covered set, unreviewed Node builtins, unlocked packages, local npm paths outside the covered
set, non-HTTPS package artifacts, missing SHA-512 lock integrity, and symlinks. Commit the generated
manifest with the reviewed site change. In ARC previews, run
`ARC_SITE_DIR=/path/to/arc-site npm run update:site-binding`, inspect the one binding diff, and rerun
both repositories' gates. Never hand-edit either digest.

Covered source trees allow only `.mjs` modules plus the exact reviewed local-override `package.json`;
`.js`, `.cjs`, TypeScript, native/Wasm, extensionless, and other future executable suffixes fail
closed. Paths use a portable ASCII allowlist and byte-stable ordering, never locale-dependent sort.
