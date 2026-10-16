// sigill-ai/evidence-action — Actions glue: inputs, files, release upload, summary.
import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import { AUDIENCE, SigillClient, escapeHtml, evidenceUrl, hashFile, isEvidenceFile } from './sigill.js';

const bool = name => core.getBooleanInput(name);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

async function findFiles(patterns) {
  const globber = await glob.create(patterns, { matchDirectories: false });
  const files = (await globber.glob()).filter(f => !isEvidenceFile(f) && statSync(f).isFile());
  return [...new Set(files)].sort();
}

// The release this run belongs to: the event's own release, else the tag ref.
async function findRelease(token) {
  const repo = process.env.GITHUB_REPOSITORY;
  const api = process.env.GITHUB_API_URL ?? 'https://api.github.com';
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  let release = null;
  try {
    release = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')).release ?? null;
  } catch { /* no event payload */ }
  if (!release && process.env.GITHUB_REF?.startsWith('refs/tags/')) {
    const tag = process.env.GITHUB_REF.slice('refs/tags/'.length);
    const res = await fetch(`${api}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, { headers });
    if (res.ok) release = await res.json();
  }
  if (!release) throw new Error("attach-to-release: this run has no GitHub release. Run on 'release' events or on a tag that has a release.");
  return { release, api, repo, headers };
}

async function attach({ release, api, repo, headers }, path) {
  const name = basename(path);
  // Re-runs replace the earlier evidence file of the same name.
  const assets = await (await fetch(`${api}/repos/${repo}/releases/${release.id}/assets?per_page=100`, { headers })).json();
  const old = Array.isArray(assets) ? assets.find(a => a.name === name) : null;
  if (old) await fetch(`${api}/repos/${repo}/releases/assets/${old.id}`, { method: 'DELETE', headers });
  const upload = release.upload_url.replace(/\{.*\}$/, '') + `?name=${encodeURIComponent(name)}`;
  const body = readFileSync(path);
  const res = await fetch(upload, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream' }, body });
  if (!res.ok) {
    const hint = res.status === 403 ? " The job needs 'permissions: contents: write' to attach files to the release." : '';
    throw new Error(`Uploading ${name} to the release failed (${res.status}).${hint}`);
  }
}

async function run() {
  const mode = core.getInput('mode') || 'timestamp';
  if (!['timestamp', 'seal'].includes(mode)) throw new Error(`mode must be 'timestamp' or 'seal', not '${mode}'.`);
  const pqc = bool('pqc');
  if (pqc && mode !== 'seal') throw new Error("pqc applies to seals: set mode: seal.");
  const certificate = core.getInput('certificate').trim();
  const attachToRelease = bool('attach-to-release');
  const apiUrl = core.getInput('api-url') || 'https://api.sigill.ai';
  const appUrl = core.getInput('app-url') || 'https://sigill.ai';

  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL)
    throw new Error("The job cannot request a GitHub identity token. Add 'permissions: id-token: write' to the job or workflow.");

  const files = await findFiles(core.getInput('files', { required: true }));
  if (!files.length) throw new Error(`No files match: ${core.getInput('files')}`);
  core.info(`${plural(files.length, 'file')} to ${mode === 'seal' ? 'seal' : 'timestamp'}. Only their digests are sent to Sigill.`);

  const client = new SigillClient({ apiUrl, getIdToken: () => core.getIDToken(AUDIENCE), onToken: t => core.setSecret(t) });
  const release = attachToRelease ? await findRelease(core.getInput('github-token')) : null;

  const results = [];
  for (const file of files) {
    const name = basename(file);
    const { sha256, sha512 } = await hashFile(file, { sha512: pqc });
    const out = mode === 'seal'
      ? await client.seal({ sha256, sha512, label: name, certificate, pqc })
      : await client.timestamp({ sha256, label: name });
    const evidenceFile = `${file}.${mode === 'seal' ? 'p7s' : 'tsr'}`;
    writeFileSync(evidenceFile, out.bytes);
    if (release) await attach(release, evidenceFile);
    const url = evidenceUrl(appUrl, mode, out.evidenceId);
    results.push({ file, sha256, evidenceFile, evidenceId: out.evidenceId, url, certificateId: out.certificateId ?? null, pqc: !!out.pqc });
    core.info(`✓ ${name} → ${basename(evidenceFile)}${url ? `  ${url}` : ''}`);
  }

  core.setOutput('evidence', JSON.stringify(results));
  core.setOutput('evidence-files', results.map(r => r.evidenceFile).join('\n'));

  const kind = mode === 'seal' ? (pqc ? 'Seal (CAdES + ML-DSA-87)' : 'Seal (CAdES)') : 'Timestamp (RFC 3161)';
  await core.summary
    .addHeading('Sigill evidence', 3)
    .addRaw(`${plural(results.length, 'file')} · ${kind}${release ? ' · attached to the release' : ''}. Only digests left the runner.`, true)
    .addTable([
      [{ data: 'File', header: true }, { data: 'SHA-256', header: true }, { data: 'Evidence', header: true }],
      ...results.map(r => [
        escapeHtml(basename(r.file)),
        `<code>${r.sha256.slice(0, 16)}…</code>`,
        r.url ? `<a href="${escapeHtml(r.url)}">${escapeHtml(basename(r.evidenceFile))}</a>` : escapeHtml(basename(r.evidenceFile)),
      ]),
    ])
    .addRaw('Anyone can check a file against its evidence at <a href="https://sigill.ai/verify">sigill.ai/verify</a>.', true)
    .write();
}

run().catch(e => core.setFailed(e.message));
