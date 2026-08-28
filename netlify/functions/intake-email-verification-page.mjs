const PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Confirm your email — ARC</title>
  <style>
    :root{color-scheme:dark;--paper:#f3efe6;--accent:#d8f76c}*{box-sizing:border-box}
    body{margin:0;background:#060606;color:var(--paper);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}
    main{min-height:100vh;display:grid;place-items:center;padding:24px}.card{width:min(620px,100%);background:#101010;border:1px solid #ffffff24;border-radius:38px;padding:clamp(32px,7vw,64px);box-shadow:0 40px 120px #0008}
    .brand{font-size:13px;font-weight:900;letter-spacing:.15em;text-transform:uppercase;margin:0 0 28px;color:#aaa49b}h1{font-size:clamp(44px,9vw,78px);line-height:.9;letter-spacing:-.06em;margin:0 0 24px}p{font-size:clamp(17px,3vw,21px);line-height:1.5;margin:0;color:#cfc9bf;font-weight:700}
    @media(max-width:520px){main{padding:12px}.card{border-radius:28px}}
  </style>
</head>
<body><main><section class="card"><p class="brand">ARC WEB</p><h1 id="heading">Confirming your email…</h1><p id="status" role="status" aria-live="polite">One moment.</p></section></main>
<script>
(() => {
  'use strict';
  const heading = document.getElementById('heading');
  const status = document.getElementById('status');
  const token = location.hash.slice(1);
  history.replaceState(null, '', '/verify/');
  const fail = () => {
    heading.textContent = 'This link cannot be used';
    status.textContent = 'It may be invalid, expired, or already used.';
  };
  if (!/^arcv1\\.[A-Za-z0-9_-]{43}$/.test(token)) { fail(); return; }
  fetch('/api/intake/verify', {
    method: 'POST',
    credentials: 'same-origin',
    referrerPolicy: 'no-referrer',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ schema: 'arc-intake-email-verification-request-v1', token })
  }).then((response) => {
    if (!response.ok) throw new Error('rejected');
    heading.textContent = 'Email confirmed';
    status.textContent = 'Your free website preview is now in the queue. We’ll email it when it’s ready. You can close this page.';
  }).catch(fail);
})();
</script></body></html>`;

export function createIntakeEmailVerificationPageHandler() {
  return async (request) => {
    if (request.method !== 'GET') return new Response(null, { status: 405, headers: { Allow: 'GET' } });
    let url;
    try { url = new URL(request.url); } catch { return new Response(null, { status: 404 }); }
    if (url.origin !== 'https://arcweb.onl' || url.pathname !== '/verify/' || url.search || url.hash) {
      return new Response(null, { status: 404 });
    }
    return new Response(PAGE, { status: 200, headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; img-src 'none'; object-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-Robots-Tag': 'noindex, nofollow, noarchive',
    } });
  };
}

export default createIntakeEmailVerificationPageHandler();
export const config = { path: '/verify/', method: 'GET' };
