(() => {
  'use strict';
  const rawFragment = location.hash;
  history.replaceState(null, '', '/claim/');

  const status = document.getElementById('claim-status');
  const renewButton = document.getElementById('claim-renew');
  const fail = (renewable = false) => {
    document.title = 'ARC handoff unavailable';
    document.getElementById('claim-title').textContent = 'This invitation is unavailable.';
    status.textContent = renewable
      ? 'This link may have expired. Request one fresh ownership email below.'
      : 'It may be invalid, expired, or already used. Open the newest ARC ownership email and try again.';
    renewButton.hidden = !renewable;
  };
  const match = rawFragment.match(/^#arc2\.([a-f0-9]{64})\.([A-Za-z0-9_-]{43})$/);
  if (!match) {
    fail();
    return;
  }

  const [, handoffId, bearer] = match;
  renewButton.addEventListener('click', async () => {
    renewButton.disabled = true;
    status.textContent = 'Requesting one fresh ownership link…';
    try {
      const response = await fetch('/api/arc2/claim-link-renew', {
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
      });
      const text = await response.text();
      if (response.status !== 202 || text.length < 2 || text.length > 512 ||
          (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
        throw new Error('claim_renewal_failed');
      }
      const value = JSON.parse(text);
      if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
          JSON.stringify(Object.keys(value)) !== JSON.stringify(['status']) ||
          value.status !== 'fresh_ownership_link_queued') throw new Error('claim_renewal_invalid');
      document.title = 'ARC ownership email requested';
      document.getElementById('claim-title').textContent = 'Check your email.';
      status.textContent = 'We queued one fresh ownership link. Only the newest link will work.';
      renewButton.hidden = true;
    } catch {
      status.textContent = 'We could not send a fresh link. Open the newest ARC ownership email and try again later.';
    }
  }, { once: true });

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
        (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      const error = new Error('claim_exchange_failed');
      error.renewable = response.status === 401;
      throw error;
    }
    const value = JSON.parse(text);
    if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
        JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['claim_url'])) throw new Error('claim_exchange_invalid');
    const target = new URL(value.claim_url);
    if (target.protocol !== 'https:' || target.hostname !== 'app.netlify.com' || target.port ||
        target.pathname !== '/claim' || target.search || target.username || target.password ||
        !/^#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(target.hash)) throw new Error('claim_target_invalid');
    status.textContent = 'Opening Netlify. Sign in to the intended business account to finish the claim.';
    location.replace(target.toString());
  }).catch((error) => fail(error?.renewable === true));
})();
