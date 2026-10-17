import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { SigillClient, SigillError, escapeHtml, evidenceUrl, hashFile, isEvidenceFile } from '../src/sigill.js';

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

function fakeApi(handlers) {
  const calls = [];
  const fetch = async (url, init) => {
    const path = new URL(url).pathname;
    calls.push({ path, init, body: init.body ? JSON.parse(init.body) : null });
    return handlers[path](init, calls);
  };
  return { fetch, calls };
}

test('hashFile streams SHA-256, and SHA-512 only when asked', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigill-'));
  const f = join(dir, 'a.bin');
  const data = Buffer.from('release bytes');
  writeFileSync(f, data);
  const h = await hashFile(f);
  assert.equal(h.sha256, createHash('sha256').update(data).digest('hex'));
  assert.equal(h.sha512, null);
  assert.equal((await hashFile(f, { sha512: true })).sha512, createHash('sha512').update(data).digest('hex'));
});

test('exchange sends the GitHub token as Bearer and reuses the Sigill token', async () => {
  let ids = 0;
  const api = fakeApi({
    '/api/ci/github/token': () => json(200, { accessToken: 'sigill-ci' }),
    '/tsa/stamp-hash': () => json(200, { transactionId: 'tx-1', tsrBase64: Buffer.from('tsr').toString('base64') }),
  });
  const c = new SigillClient({ apiUrl: 'https://api.sigill.ai/', getIdToken: async () => `oidc-${++ids}`, fetch: api.fetch });
  const a = await c.timestamp({ sha256: 'ab', label: 'a' });
  await c.timestamp({ sha256: 'cd', label: 'b' });
  assert.equal(api.calls[0].init.headers.Authorization, 'Bearer oidc-1');
  assert.equal(api.calls.filter(x => x.path === '/api/ci/github/token').length, 1);
  assert.equal(api.calls[1].init.headers.Authorization, 'Bearer sigill-ci');
  assert.deepEqual(api.calls[1].body, { hashHex: 'ab', label: 'a' });
  assert.equal(a.evidenceId, 'tx-1');
  assert.equal(a.bytes.toString(), 'tsr');
});

test('a fresh GitHub token is exchanged before the Sigill token can expire', async () => {
  let t = 0, ids = 0;
  const api = fakeApi({
    '/api/ci/github/token': () => json(200, { accessToken: `sigill-${ids}` }),
    '/tsa/stamp-hash': () => json(200, { transactionId: 'x', tsrBase64: '' }),
  });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => `oidc-${++ids}`, fetch: api.fetch, now: () => t });
  await c.timestamp({ sha256: 'a' });
  t = 13 * 60 * 1000;
  await c.timestamp({ sha256: 'b' });
  assert.equal(ids, 2, 'GitHub OIDC tokens are single use at Sigill; each exchange needs a new one');
});

test('seal: pqc sends SHA-512, certificate is optional, ids come from headers', async () => {
  const api = fakeApi({
    '/api/ci/github/token': () => json(200, { accessToken: 't' }),
    '/seal/sign-hash': () => new Response(Buffer.from('p7s'), {
      status: 200, headers: { 'X-Seal-Operation-Id': 'op-1', 'X-Seal-Certificate-Id': 'cert-1' },
    }),
  });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => 'o', fetch: api.fetch });
  const s = await c.seal({ sha256: 'aa', sha512: 'bb', label: 'app.tgz', certificate: '', pqc: true });
  assert.deepEqual(api.calls[1].body, { hashHex: 'aa', label: 'app.tgz', pqc: true, hashHex512: 'bb' });
  assert.equal(s.evidenceId, 'op-1');
  assert.equal(s.certificateId, 'cert-1');
  await c.seal({ sha256: 'aa', label: 'x', certificate: 'c-9', pqc: false });
  assert.deepEqual(api.calls[2].body, { hashHex: 'aa', label: 'x', pqc: false, certificateId: 'c-9' });
});

test('errors carry the code and a hint the user can act on', async () => {
  const api = fakeApi({ '/api/ci/github/token': () => json(403, { code: 'repository_not_covered' }) });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => 'o', fetch: api.fetch });
  await assert.rejects(c.timestamp({ sha256: 'a' }), e =>
    e instanceof SigillError && e.code === 'repository_not_covered' && /Configure/.test(e.message));
});

test('an HTML 403 from the edge is not dumped into the log', async () => {
  const api = fakeApi({ '/api/ci/github/token': () => new Response('<html>blocked</html>', { status: 403 }) });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => 'o', fetch: api.fetch });
  await assert.rejects(c.timestamp({ sha256: 'a' }), e => !e.message.includes('<html>') && /refused before it reached Sigill/.test(e.message));
});

test('evidence links and evidence-file filter', () => {
  assert.equal(evidenceUrl('https://sigill.ai/', 'seal', 'op'), 'https://sigill.ai/evidences/op?type=seal');
  assert.equal(evidenceUrl('https://sigill.ai', 'timestamp', 'tx'), 'https://sigill.ai/evidences/tx');
  assert.equal(evidenceUrl('https://sigill.ai', 'timestamp', null), null);
  assert.ok(isEvidenceFile('dist/a.tgz.p7s') && isEvidenceFile('a.TSR') && !isEvidenceFile('a.tgz'));
});

test('the Sigill token is handed to the log masker; filenames are escaped', async () => {
  const masked = [];
  const api = fakeApi({
    '/api/ci/github/token': () => json(200, { accessToken: 'secret-ci-token' }),
    '/tsa/stamp-hash': () => json(200, { transactionId: 'x', tsrBase64: '' }),
  });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => 'o', fetch: api.fetch, onToken: t => masked.push(t) });
  await c.timestamp({ sha256: 'a' });
  assert.deepEqual(masked, ['secret-ci-token']);
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>.tgz'), '&lt;img src=x onerror=alert(1)&gt;.tgz');
});

test('qualified: requested explicitly, and the step fails closed when it is not qualified', async () => {
  const p7s = qualified => () => new Response(Buffer.from('p7s'), {
    status: 200, headers: { 'X-Seal-Operation-Id': 'op-1', 'X-Seal-Qualified': qualified },
  });
  let sealQualified = 'true', stampQualified = true;
  const api = fakeApi({
    '/api/ci/github/token': () => json(200, { accessToken: 't' }),
    '/seal/sign-hash': (i, calls) => p7s(sealQualified)(i, calls),
    '/tsa/stamp-hash': () => json(200, { transactionId: 'tx', tsrBase64: 'dHNy', qualified: stampQualified }),
  });
  const c = new SigillClient({ apiUrl: 'https://x', getIdToken: async () => 'o', fetch: api.fetch });

  const s = await c.seal({ sha256: 'aa', label: 'pkg.whl', pqc: false, qualified: true });
  assert.equal(api.calls[1].body.qualified, true);
  assert.equal(s.qualified, true);
  const t = await c.timestamp({ sha256: 'aa', label: 'pkg.whl', qualified: true });
  assert.equal(api.calls[2].body.qualified, true);
  assert.equal(t.qualified, true);

  // The API seals without a timestamp when the qualified service fails: never accept that.
  sealQualified = 'false';
  await assert.rejects(c.seal({ sha256: 'aa', label: 'pkg.whl', qualified: true }), e => e.code === 'not_qualified' && /pkg\.whl/.test(e.message));
  stampQualified = false;
  await assert.rejects(c.timestamp({ sha256: 'aa', label: 'pkg.whl', qualified: true }), e => e.code === 'not_qualified');

  // Not requested: the field is not sent, and a standard timestamp is fine.
  const plain = await c.seal({ sha256: 'aa', label: 'x', pqc: false });
  assert.equal('qualified' in api.calls.at(-1).body, false);
  assert.equal(plain.qualified, false);
});
