// Test-only build identity. Runtime code still consumes only the generated module.
process.env.COMMIT_REF = '9999999999999999999999999999999999999999';
await import('./build-site.mjs');
