(() => {
  'use strict';
  const rawFragment = location.hash;
  history.replaceState(null, '', '/claim/');

  const status = document.getElementById('claim-status');
  const fail = () => {
    document.title = 'ARC handoff unavailable';
    document.getElementById('claim-title').textContent = 'This invitation is unavailable.';
    status.textContent = 'It may be invalid, expired, or already used. Contact ARC for a new secure handoff.';
  };
  const match = rawFragment.match(/^#arc2\.([a-f0-9]{64})\.([A-Za-z0-9_-]{43})$/);
  if (!match) {
    fail();
    return;
  }

  const [, handoffId, bearer] = match;
  fetch('/api/arc2/claim', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'X-ARC-Handoff-Id': handoffId,
    },
    body: null,
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  }).then(async (response) => {
    const text = await response.text();
    if (!response.ok || text.length < 2 || text.length > 2048 ||
        (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw new Error('claim_exchange_failed');
    const value = JSON.parse(text);
    if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
        JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['claim_url'])) throw new Error('claim_exchange_invalid');
    const target = new URL(value.claim_url);
    if (target.protocol !== 'https:' || target.hostname !== 'app.netlify.com' || target.port ||
        target.pathname !== '/claim' || target.search || target.username || target.password ||
        !/^#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(target.hash)) throw new Error('claim_target_invalid');
    status.textContent = 'Opening Netlify. Sign in to the intended business account to finish the claim.';
    location.replace(target.toString());
  }).catch(fail);
})();
