# Sigill Evidence Action

Timestamp and seal what your workflow builds — **RFC 3161 timestamps** and **CAdES seals**, optionally post-quantum hybrid. Files are hashed on the runner; **only digests are sent to Sigill**. No API key and no secrets: the job proves who it is with GitHub's OIDC identity token.

Setup guide: [sigill.ai/guides/connect-github](https://sigill.ai/guides/connect-github)

## Before you start

1. Connect your GitHub organisation in Sigill under **Settings → Apps**, and install the **Sigill AI** app on the repositories that should produce evidence.
2. Give the job `id-token: write`.

## Timestamp build output

```yaml
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v5
      # … build into dist/ …
      - uses: sigill-ai/evidence-action@v1
        with:
          files: dist/*
```

Each file gets a `.tsr` next to it.

## Seal release assets

```yaml
on:
  release:
    types: [published]

jobs:
  seal:
    runs-on: ubuntu-latest
    environment: release-signing   # recommended: required reviewers before anything is sealed
    permissions:
      id-token: write
      contents: write              # attach the .p7s files to the release
    steps:
      - run: gh release download "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" -D assets
        env:
          GH_TOKEN: ${{ github.token }}
      - uses: sigill-ai/evidence-action@v1
        with:
          files: assets/*
          mode: seal
          attach-to-release: true
          # certificate: <id>     # Settings → Seal certificates → Copy ID
          # pqc: true             # post-quantum hybrid: ML-DSA-87 strengthens the seal
```

Each asset ships with its `.p7s` on the release. Anyone can verify it at [sigill.ai/verify](https://sigill.ai/verify) without a Sigill account, or with any CAdES validator (checking the post-quantum part needs ML-DSA support).

## Inputs

| Input | Default | |
|---|---|---|
| `files` | — | Files to timestamp or seal, one glob per line. Existing `.tsr`/`.p7s` files are skipped. |
| `mode` | `timestamp` | `timestamp` (`.tsr`) or `seal` (detached CAdES `.p7s` with the timestamp embedded). |
| `certificate` | your only certificate, else the Sigill Platform Seal | Seal certificate ID. |
| `pqc` | `false` | Seals: post-quantum hybrid — an ML-DSA-87 signature strengthens the classic seal, so it stays trustworthy once quantum computers can break classic signatures. |
| `attach-to-release` | `false` | Upload the evidence files to this run's release. Needs `contents: write`. |

## Outputs

| Output | |
|---|---|
| `evidence` | JSON array: `file`, `sha256`, `evidenceFile`, `evidenceId`, `url`, `certificateId`, `pqc`. |
| `evidence-files` | The written `.tsr`/`.p7s` paths, one per line. |

The job summary lists every file with a link to its evidence in Sigill.

## What the evidence proves

That these exact bytes existed at the timestamp's time, that your organisation (or the Sigill Platform Seal) sealed them, and which repository, commit, workflow and run requested it — taken from GitHub's signed identity token. It does not by itself prove *how* the bytes were built; for that, add [GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations). Only runs started by push, release, schedule or `workflow_dispatch` are accepted — never pull requests.

## License

Apache-2.0

## Verify this action

Every release is sealed by this action itself. The release page carries `index.js.p7s` and `action.yml.p7s`: Sigill seals (CAdES with an embedded timestamp, post-quantum hybrid with ML-DSA-87) over `dist/index.js` and `action.yml` exactly as they are at the release tag — the files GitHub runs when you use the tag. Download both files at the tag and check them at [sigill.ai/verify](https://sigill.ai/verify). Pin a full commit SHA if you want the strongest guarantee.
