// Sigill evidence for GitHub Actions — the parts that do not depend on the
// Actions runtime, so they can be tested with a fake fetch.
//
// Trust model (see https://sigill.ai/guides/connect-github):
//   - The job proves who it is with GitHub's OIDC identity token (audience
//     https://sigill.ai) and exchanges it for a 15-minute Sigill token that can
//     only timestamp and seal. No Sigill secret is stored in GitHub.
//   - Files are hashed here, on the runner. Only digests are sent.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';

export const AUDIENCE = 'https://sigill.ai';
// Re-exchange before the 15-minute Sigill token can expire mid-batch.
const TOKEN_MAX_AGE_MS = 12 * 60 * 1000;

/** SHA-256 (always) and SHA-512 (when asked) of a file, streamed. */
export async function hashFile(path, { sha512 = false } = {}) {
  const h256 = createHash('sha256');
  const h512 = sha512 ? createHash('sha512') : null;
  for await (const chunk of createReadStream(path)) {
    h256.update(chunk);
    h512?.update(chunk);
  }
  return { sha256: h256.digest('hex'), sha512: h512 ? h512.digest('hex') : null };
}

// What each Sigill error means for the person reading the workflow log.
const HINTS = {
  github_not_connected:
    "This repository's GitHub organisation is not connected to a Sigill organisation. An owner connects it in Sigill under Settings → Apps.",
  repository_not_covered:
    'The Sigill AI app is not installed on this repository, or the installation is suspended. Add the repository in GitHub: Settings → GitHub Apps → Sigill AI → Configure.',
  event_not_trusted:
    'Sigill only accepts runs started by push, release, schedule or workflow_dispatch. Pull-request runs are never accepted.',
  certificate_required:
    "Your Sigill organisation has several seal certificates. Set the 'certificate' input to the one that should seal (Settings → Seal certificates → Copy ID).",
};

export class SigillError extends Error {
  constructor(status, code, detail) {
    const hint = HINTS[code] ??
      (status === 402 ? 'Your Sigill plan does not include this, or its quota is used up. Sealing needs the Business or Scale plan.'
        : status === 403 && !code ? 'The request was refused before it reached Sigill, or the connection no longer covers this run.'
        : null);
    super([`Sigill returned ${status}${code ? ` (${code})` : ''}.`, hint ?? detail].filter(Boolean).join(' '));
    this.status = status;
    this.code = code;
  }
}

async function fail(res) {
  let code = null, detail = null;
  const text = await res.text().catch(() => '');
  try {
    const body = JSON.parse(text);
    code = body.code ?? null;
    detail = body.detail ?? body.title ?? null;
  } catch {
    // An HTML page here means an edge in front of Sigill answered, not Sigill.
    detail = text.trimStart().startsWith('<') ? null : text.slice(0, 300) || null;
  }
  throw new SigillError(res.status, code, detail);
}

export class SigillClient {
  /**
   * @param {object} o
   * @param {string} o.apiUrl   e.g. https://api.sigill.ai
   * @param {() => Promise<string>} o.getIdToken  fresh GitHub OIDC token (single use)
   * @param {typeof fetch} [o.fetch]
   */
  constructor({ apiUrl, getIdToken, fetch: f = globalThis.fetch, now = () => Date.now(), onToken = () => {} }) {
    this.apiUrl = apiUrl.replace(/\/+$/, '');
    this.getIdToken = getIdToken;
    this.fetch = f;
    this.now = now;
    this.onToken = onToken;
    this.token = null;
    this.tokenAt = 0;
  }

  async accessToken() {
    if (this.token && this.now() - this.tokenAt < TOKEN_MAX_AGE_MS) return this.token;
    const idToken = await this.getIdToken();
    // Bearer header, not only a body field: the edge in front of Sigill
    // blocks unauthenticated requests from hosting-provider addresses.
    const res = await this.fetch(`${this.apiUrl}/api/ci/github/token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${idToken}` },
    });
    if (!res.ok) await fail(res);
    const body = await res.json();
    this.token = body.accessToken;
    this.onToken(this.token);   // mask it in the workflow log
    this.tokenAt = this.now();
    return this.token;
  }

  async post(path, json) {
    return this.fetch(`${this.apiUrl}${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${await this.accessToken()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(json),
    });
  }

  /** RFC 3161 timestamp of a SHA-256 digest. Returns the .tsr bytes and the evidence id. */
  async timestamp({ sha256, label, qualified = false }) {
    const req = { hashHex: sha256, label };
    if (qualified) req.qualified = true;
    const res = await this.post('/tsa/stamp-hash', req);
    if (!res.ok) await fail(res);
    const body = await res.json();
    if (qualified && body.qualified !== true) throw notQualified(label);
    return {
      qualified: body.qualified === true,
      bytes: Buffer.from(body.tsrBase64, 'base64'),
      evidenceId: body.transactionId ?? null,
      genTime: body.genTime ?? null,
      tsa: body.tsaName ?? null,
    };
  }

  /** Detached CAdES seal (timestamp embedded). Returns the .p7s bytes and ids. */
  async seal({ sha256, sha512, label, certificate, pqc, qualified = false }) {
    const req = { hashHex: sha256, label, pqc: !!pqc };
    if (qualified) req.qualified = true;
    if (pqc) req.hashHex512 = sha512;
    if (certificate) req.certificateId = certificate;
    const res = await this.post('/seal/sign-hash', req);
    if (!res.ok) await fail(res);
    const isQualified = (res.headers.get('x-seal-qualified') ?? '').toLowerCase() === 'true';
    // Fail closed: a seal whose qualified timestamp could not be embedded is
    // not what was asked for, and must never be shipped as if it were.
    if (qualified && !isQualified) throw notQualified(label);
    return {
      qualified: isQualified,
      bytes: Buffer.from(await res.arrayBuffer()),
      evidenceId: res.headers.get('x-seal-operation-id'),
      certificateId: res.headers.get('x-seal-certificate-id'),
      pqc: (res.headers.get('x-seal-pqc') ?? '').toLowerCase() === 'true' || !!pqc,
    };
  }
}

function notQualified(label) {
  return Object.assign(new Error(
    `Sigill did not return a qualified timestamp for ${label ?? 'the file'}. No evidence file was written. Qualified timestamps need the Business or Scale plan (or trial credits) and an available qualified service — re-run, or set qualified: false.`), { code: 'not_qualified' });
}

/** Link to the evidence record in Sigill (seals and timestamps live under one route). */
export function evidenceUrl(appUrl, mode, evidenceId) {
  if (!evidenceId) return null;
  const base = appUrl.replace(/\/+$/, '');
  return mode === 'seal' ? `${base}/evidences/${evidenceId}?type=seal` : `${base}/evidences/${evidenceId}`;
}

/** Evidence files the action writes must never be picked up as inputs on a re-run. */
export const isEvidenceFile = p => /\.(tsr|p7s)$/i.test(p);

/** Filenames come from the build; never let them become markup in the job summary. */
export const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
