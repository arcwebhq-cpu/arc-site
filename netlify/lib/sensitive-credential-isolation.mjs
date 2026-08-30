export function sensitiveCredentialsAreIsolated(env = {}, requiredNames = []) {
  if (!env || typeof env !== 'object' || Array.isArray(env) || !Array.isArray(requiredNames) ||
      requiredNames.length < 1 || new Set(requiredNames).size !== requiredNames.length) return false;
  const required = requiredNames.map((name) => ({ name, value: env[name] }));
  if (required.some(({ name, value }) => typeof name !== 'string' || name.length === 0 ||
      typeof value !== 'string' || value.length === 0)) return false;
  // Compare against every configured string. A credential copied into a
  // misleadingly named variable must not bypass isolation by avoiding a
  // SECRET/TOKEN/KEY suffix.
  const configured = Object.entries(env).filter(([, value]) =>
    typeof value === 'string' && value.length > 0);
  return required.every(({ name, value }) => configured.every(([otherName, otherValue]) =>
    otherName === name || otherValue !== value));
}
