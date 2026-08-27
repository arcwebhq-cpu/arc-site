(() => {
  'use strict';
  const form = document.getElementById('support-form');
  const submit = document.getElementById('support-submit');
  const status = document.getElementById('support-status');
  let requestId = crypto.randomUUID();
  let formStartedAt = Date.now();
  let sending = false;

  const setSending = (value) => {
    sending = value;
    for (const control of form.elements) control.disabled = value;
    submit.disabled = value;
  };
  const readJson = async (response) => {
    const type = (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
    const text = await response.text();
    if (type !== 'application/json' || text.length < 2 || text.length > 4096) throw new Error('invalid_response');
    return JSON.parse(text);
  };

  submit.disabled = false;
  status.textContent = 'Ready.';
  form.addEventListener('input', () => {
    if (!sending) requestId = crypto.randomUUID();
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (sending || !form.reportValidity()) return;
    const values = new FormData(form);
    const payload = {
      request_id: requestId,
      form_started_at: formStartedAt,
      name: String(values.get('name') || ''),
      email: String(values.get('email') || ''),
      business: String(values.get('business') || ''),
      category: String(values.get('category') || ''),
      project_url: String(values.get('project_url') || ''),
      details: String(values.get('details') || ''),
      company_website: String(values.get('company_website') || ''),
    };
    setSending(true);
    status.textContent = 'Sending your request.';
    try {
      const response = await fetch('/api/support/request', {
        method: 'POST', cache: 'no-store', credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const result = await readJson(response);
      if (!response.ok || result.schema !== 'arc-support-request-accepted-v1' || result.accepted !== true ||
          result.request_id !== requestId) throw new Error(result.error || 'request_failed');
      form.reset();
      status.textContent = `Request received. Reference: ${result.request_id}`;
      requestId = crypto.randomUUID();
      formStartedAt = Date.now();
    } catch {
      status.textContent = 'We could not confirm your request. Keep this page open and try again.';
    } finally {
      setSending(false);
      status.focus();
    }
  });
})();
