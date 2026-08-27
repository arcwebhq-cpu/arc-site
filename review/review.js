(() => {
  'use strict';

  const rawFragment = location.hash;
  history.replaceState(null, '', location.pathname + location.search);

  const status = document.getElementById('review-status');
  const workspace = document.getElementById('review-workspace');
  const previewLink = document.getElementById('preview-link');
  const rounds = document.getElementById('revision-rounds');
  const actions = document.getElementById('review-actions');
  const approveButton = document.getElementById('approve-button');
  const changesButton = document.getElementById('changes-button');
  const changesForm = document.getElementById('changes-form');
  const revisionNotes = document.getElementById('revision-notes');
  const cancelChanges = document.getElementById('cancel-changes');
  let current = null;
  let pendingDecisionKey = null;

  const fail = (message = 'This private review is unavailable. Open the newest ARC review link.') => {
    document.title = 'ARC review unavailable';
    status.textContent = message;
    workspace.hidden = true;
  };

  const requestJson = async (path, options = {}) => {
    const response = await fetch(path, {
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      ...options,
    });
    const text = await response.text();
    if (text.length < 2 || text.length > 8192 ||
        (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      throw new Error('invalid_response');
    }
    const value = JSON.parse(text);
    if (!response.ok) {
      const error = new Error(typeof value?.error === 'string' ? value.error : 'request_failed');
      error.code = value?.error;
      throw error;
    }
    return value;
  };

  const validPreview = (value) => {
    const target = new URL(value);
    if (target.protocol !== 'https:' || target.origin !== 'https://arcwebhq-cpu.github.io' ||
        target.username || target.password || target.search || target.hash || !target.pathname.endsWith('/')) {
      throw new Error('invalid_preview');
    }
    return target.href;
  };

  const render = (value) => {
    current = value;
    previewLink.href = validPreview(value.preview_url);
    workspace.hidden = false;
    changesForm.hidden = true;
    actions.hidden = false;
    if (value.state === 'OPEN') {
      status.textContent = 'View every page, then choose one next step.';
      rounds.textContent = value.revision_rounds_remaining === 0
        ? 'Both included revision rounds have been used.'
        : `${value.revision_rounds_remaining} revision round${value.revision_rounds_remaining === 1 ? '' : 's'} remaining.`;
      approveButton.textContent = 'Approve & Pay';
      approveButton.disabled = !value.can_approve_and_pay;
      changesButton.disabled = !value.can_request_changes;
      if (!value.can_approve_and_pay) status.textContent = 'Your preview is ready. Secure checkout is temporarily unavailable.';
    } else if (value.state === 'APPROVED') {
      status.textContent = 'Your approval is saved. Continue to secure checkout.';
      rounds.textContent = 'This approval is bound to the exact preview shown here.';
      approveButton.textContent = 'Continue to Payment';
      approveButton.disabled = false;
      changesButton.disabled = true;
    } else if (value.state === 'REVISION_REQUESTED') {
      status.textContent = 'Changes requested. We’ll email a new private review link when the revised preview is ready. No reply needed.';
      rounds.textContent = '';
      actions.hidden = true;
    } else if (value.state === 'REVISION_SUPERSEDED') {
      status.textContent = 'A newer preview is ready. Open the newest private review link.';
      rounds.textContent = '';
      actions.hidden = true;
    } else {
      throw new Error('invalid_state');
    }
  };

  const loadStatus = async () => render(await requestJson('/api/review/status'));

  const exchange = async () => {
    const match = rawFragment.match(/^#invite=([A-Za-z0-9_-]{43,128})$/);
    if (!match) return;
    await requestJson('/api/review/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ invite_token: match[1] }),
    });
  };

  const openCheckout = async () => {
    const value = await requestJson('/api/review/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const target = new URL(value.checkout_url);
    const checkoutPath = /^\/c\/pay\/cs_(?:test|live)_[A-Za-z0-9_]{8,512}$/;
    const safeFragment = target.hash === '' ||
      (target.hash.length >= 17 && target.hash.length <= 4096 && !/[\\\u0000-\u001f\u007f]/.test(target.hash));
    if (target.protocol !== 'https:' || target.origin !== 'https://checkout.stripe.com' ||
        target.username || target.password || target.search || !checkoutPath.test(target.pathname) ||
        !safeFragment) throw new Error('invalid_checkout');
    location.assign(target.href);
  };

  approveButton.addEventListener('click', async () => {
    approveButton.disabled = true;
    status.textContent = current?.state === 'APPROVED' ? 'Opening secure checkout.' : 'Saving your approval.';
    try {
      if (current?.state !== 'APPROVED') {
        pendingDecisionKey ||= crypto.randomUUID();
        await requestJson('/api/review/decision', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'APPROVE_AND_PAY',
            expected_revision: current.record_revision,
            idempotency_key: pendingDecisionKey,
          }),
        });
        pendingDecisionKey = null;
      }
      await openCheckout();
    } catch (error) {
      await loadStatus().catch(() => {});
      status.textContent = error?.code === 'checkout_unavailable'
        ? 'Your approval is safe. Secure checkout is temporarily unavailable.'
        : 'We could not open checkout. Try again from this private page.';
      approveButton.disabled = false;
    }
  });

  changesButton.addEventListener('click', () => {
    actions.hidden = true;
    changesForm.hidden = false;
    revisionNotes.focus();
  });
  cancelChanges.addEventListener('click', () => {
    changesForm.hidden = true;
    actions.hidden = false;
    changesButton.focus();
  });
  changesForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!changesForm.reportValidity()) return;
    const submit = changesForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    status.textContent = 'Saving your change request.';
    try {
      pendingDecisionKey ||= crypto.randomUUID();
      await requestJson('/api/review/decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'REQUEST_CHANGES',
          expected_revision: current.record_revision,
          idempotency_key: pendingDecisionKey,
          revision_notes: revisionNotes.value,
        }),
      });
      pendingDecisionKey = null;
      await loadStatus();
    } catch {
      status.textContent = 'We could not save that request. Check this page and try again.';
      submit.disabled = false;
    }
  });

  exchange().then(loadStatus).catch(() => fail());
})();
