#!/usr/bin/env node
// Build-only diagnostic. No build/publish, SDK, storage, endpoint or file writes.
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';

export const SCHEMA = 'arc-live-stripe-binding-probe-v1';
export const SITE_ID = '8f9d462c-952f-42fc-a3a0-50a2529e8f5d';
export const ENDPOINT = 'https://api.stripe.com/v1/account';
export const API_VERSION = '2026-08-26.dahlia';
export const ROLE_NAMES = Object.freeze([
  'ARC_STRIPE_REVIEW_SECRET_KEY',
  'ARC_STRIPE_ACCOUNT_VERIFICATION_KEY',
  'ARC_STRIPE_PAYMENT_INTENT_VERIFICATION_KEY',
]);
export const BUILD_STOP_EXIT_CODE = 2;
const MAX_BYTES = 256 * 1024;
const TIMEOUT_MS = 5000;
const LIVE_KEY = /^rk_live_[A-Za-z0-9_]{16,240}$/;
const SHA = /^[a-f0-9]{40}$/;
const HEX = /^[a-f0-9]{64}$/;
const REQUEST_ID = /^req_[A-Za-z0-9]{6,128}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const present = value => typeof value === 'string' && value.length > 0;
const initialRows = env => ROLE_NAMES.map(role => ({role, present: present(env[role]),
  live_format: typeof env[role] === 'string' && LIVE_KEY.test(env[role]),
  http_status: null, request_id: null, reason: 'NOT_ATTEMPTED'}));
const failure = code => { throw Object.freeze({probeCode: code}); };
const CODES = new Set(['TIME_LIMIT','RESPONSE_TOO_LARGE','RESPONSE_INVALID','ACCOUNT_INVALID','NETWORK_ERROR']);
const cancel = body => { try { Promise.resolve(body?.cancel()).catch(() => {}); } catch {} };

function contextReason(env, expectedSha, expectedAccountSha) {
  if (!SHA.test(expectedSha || '') || !SHA.test(env.COMMIT_REF || '') || env.COMMIT_REF !== expectedSha)
    return 'COMMIT_PIN_INVALID';
  if (env.NETLIFY !== 'true' || env.SITE_ID !== SITE_ID || env.CONTEXT !== 'production' || env.BRANCH !== 'main')
    return 'BUILD_CONTEXT_INVALID';
  // Includes candidate-only gates. Missing gates stay OFF; no scope/flag is set.
  if (Object.entries(env).some(([name,value]) =>
    (/^ARC(?:1)?_[A-Z0-9_]*ENABLED$/.test(name) || name === 'ARC_ALLOW_TEST_MODE_EVENTS') &&
    value !== undefined && value !== 'false')) return 'BUSINESS_GATE_NOT_OFF';
  if (!HEX.test(expectedAccountSha || '') ||
      (env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 && env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256 !== expectedAccountSha))
    return 'ACCOUNT_PIN_INVALID';
  return null;
}

async function accountJson(response) {
  if (response.headers.get('content-type')?.split(';',1)[0].trim().toLowerCase() !== 'application/json') {
    cancel(response.body); failure('RESPONSE_INVALID');
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d{1,8}$/.test(declared) || Number(declared) > MAX_BYTES)) {
    cancel(response.body); failure('RESPONSE_TOO_LARGE');
  }
  const reader = response.body?.getReader?.();
  if (!reader) failure('RESPONSE_INVALID');
  let length = 0; const chunks = [];
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      if (!(item.value instanceof Uint8Array)) failure('RESPONSE_INVALID');
      length += item.value.byteLength;
      if (length > MAX_BYTES) failure('RESPONSE_TOO_LARGE');
      chunks.push(Buffer.from(item.value));
    }
    let value;
    try { value = JSON.parse(Buffer.concat(chunks,length).toString('utf8')); }
    catch { failure('RESPONSE_INVALID'); }
    if (!value || Array.isArray(value) || value.object !== 'account' ||
        typeof value.id !== 'string' || !/^acct_[A-Za-z0-9]{6,128}$/.test(value.id)) failure('ACCOUNT_INVALID');
    return value.id;
  } finally {
    try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
    try { reader.releaseLock(); } catch {}
  }
}

async function readRole(row, key, expectedAccountHash, fetchImpl, timeoutMs) {
  const controller = new AbortController(); let timer;
  const observed = {http_status:null,request_id:null};
  const deadline = new Promise((_,reject) => { timer = setTimeout(() => {
    controller.abort(); reject(Object.freeze({probeCode:'TIME_LIMIT'}));
  }, timeoutMs); });
  const work = async () => {
    const result = {...row};
    let response;
    try { response = await fetchImpl(ENDPOINT, {method:'GET', redirect:'error', cache:'no-store',
      credentials:'omit', signal:controller.signal,
      headers:{Accept:'application/json', Authorization:`Bearer ${key}`, 'Stripe-Version':API_VERSION}}); }
    catch { failure('NETWORK_ERROR'); }
    if (controller.signal.aborted) { cancel(response?.body); failure('TIME_LIMIT'); }
    if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599 ||
        response.redirected !== false || response.url !== ENDPOINT || typeof response.headers?.get !== 'function') {
      cancel(response?.body); failure('RESPONSE_INVALID');
    }
    observed.http_status = result.http_status = response.status;
    const id = response.headers.get('request-id');
    observed.request_id = result.request_id = typeof id === 'string' && REQUEST_ID.test(id) ? id : null;
    if (response.status !== 200) {
      cancel(response.body); // Never parse or return provider error bodies.
      result.reason = response.status === 403 ? 'ACCOUNT_READ_DENIED' :
        response.status === 401 ? 'AUTHENTICATION_FAILED' :
        response.status >= 300 && response.status < 400 ? 'REDIRECT_REJECTED' : 'HTTP_FAILURE';
      return result;
    }
    const accountId = await accountJson(response);
    result.account_match = digest(accountId) === expectedAccountHash;
    result.reason = result.account_match ? (result.request_id ? 'ACCOUNT_MATCH' : 'REQUEST_ID_UNAVAILABLE') : 'FOREIGN_ACCOUNT';
    return result;
  };
  try { Object.assign(row, await Promise.race([work(),deadline])); }
  catch (error) { Object.assign(row,observed); row.reason = CODES.has(error?.probeCode) ? error.probeCode : 'NETWORK_ERROR'; }
  finally { clearTimeout(timer); controller.abort(); }
}

export async function probeBindings({env = process.env, expectedSha,
  expectedAccountSha = env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256, fetchImpl = globalThis.fetch,
  timeoutMs = TIMEOUT_MS} = {}) {
  const rows = initialRows(env);
  const blocked = contextReason(env,expectedSha,expectedAccountSha);
  if (blocked) { rows.forEach(row => {row.reason=blocked;}); return {schema:SCHEMA,roles:rows}; }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TIMEOUT_MS || typeof fetchImpl !== 'function') {
    rows.forEach(row => {row.reason='PROBE_CONFIGURATION_INVALID';}); return {schema:SCHEMA,roles:rows};
  }
  const keys = ROLE_NAMES.map(name => env[name]);
  for (let index=0;index<rows.length;index++) {
    const row=rows[index];
    if (!row.present) row.reason='MISSING_BINDING';
    else if (!row.live_format) row.reason='LIVE_FORMAT_INVALID';
    else if (keys.some((key,other)=>other!==index && key===keys[index])) row.reason='ROLE_BINDINGS_NOT_DISTINCT';
  }
  for (let index=0;index<rows.length;index++) {
    if (rows[index].reason!=='NOT_ATTEMPTED') continue;
    await readRole(rows[index],keys[index],expectedAccountSha,fetchImpl,timeoutMs);
    if (rows[index].reason === 'FOREIGN_ACCOUNT' || rows[index].reason === 'AUTHENTICATION_FAILED') {
      for (const row of rows.slice(index+1)) if(row.reason==='NOT_ATTEMPTED') row.reason='NOT_ATTEMPTED_INVALID_ACCOUNT';
      break;
    }
  }
  return {schema:SCHEMA,roles:rows};
}

// Read only the local commit graph; no shell, remote Git operation or credentials.
export function localHeadParent({cwd=process.cwd()}={}) {
  const read=(args,maxBuffer)=>execFileSync('git',['--no-pager',...args],{
    cwd,encoding:'utf8',timeout:2000,maxBuffer,stdio:['ignore','pipe','pipe'],
    env:{PATH:process.env.PATH || '/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',
      GIT_CONFIG_SYSTEM:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1',GIT_NO_LAZY_FETCH:'1'},
  });
  const head=read(['rev-parse','--verify','HEAD^{commit}'],256).trim();
  // Read parent IDs from the actual commit header, including shallow clones.
  // Do not resolve/fetch the parent object, save commit messages, or print Git output.
  const header=read(['cat-file','-p',head],262144).split('\n\n',1)[0];
  const parents=header.split('\n').filter(line=>line.startsWith('parent ')).map(line=>line.slice(7));
  if (!SHA.test(head) || parents.length!==1 || !SHA.test(parents[0])) return '';
  return head+' '+parents[0];
}

function cliPins(args,env,readHeadParent) {
  const allowed = new Set(['--expected-sha','--expected-parent-sha','--expected-account-sha']);
  const pins = {};
  if (!Array.isArray(args) || args.length < 2 || args.length > 4 || args.length % 2) return {};
  for (let i=0;i<args.length;i+=2) {
    if (!allowed.has(args[i]) || Object.hasOwn(pins,args[i]) || typeof args[i+1] !== 'string') return {};
    pins[args[i]]=args[i+1];
  }
  if (Boolean(pins['--expected-sha']) === Boolean(pins['--expected-parent-sha'])) return {};
  let expectedSha = pins['--expected-sha'];
  if (pins['--expected-parent-sha']) {
    if (!SHA.test(pins['--expected-parent-sha'])) return {};
    let parts; try { parts=readHeadParent().split(' '); } catch { return {}; }
    if (parts.length!==2 || !parts.every(value=>SHA.test(value)) || parts[0]!==env.COMMIT_REF ||
        parts[1]!==pins['--expected-parent-sha']) return {};
    expectedSha=parts[0];
  }
  return {expectedSha,expectedAccountSha:pins['--expected-account-sha'] || env.ARC_EXPECTED_STRIPE_ACCOUNT_ID_SHA256};
}

export async function runCli({args = process.argv.slice(2), env = process.env,
  fetchImpl = globalThis.fetch, write = text => process.stdout.write(text), timeoutMs = TIMEOUT_MS,
  readHeadParent = localHeadParent} = {}) {
  let report;
  try {
    report = await probeBindings({env,...cliPins(args,env,readHeadParent),fetchImpl,timeoutMs});
  } catch {
    report = {schema:SCHEMA,roles:ROLE_NAMES.map(role=>({role,present:false,live_format:false,
      http_status:null,request_id:null,reason:'PROBE_INTERNAL_FAILURE'}))};
  }
  try { write(JSON.stringify(report)+'\n'); } catch { /* Never emit an exception. */ }
  return BUILD_STOP_EXIT_CODE; // Even all three matches are NOT authorization to publish.
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runCli();
}
