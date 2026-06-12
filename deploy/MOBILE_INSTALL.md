# Mobile SSH Install Flow

This document describes the repository-side protocol for an Android/Kotlin app that installs Ultra directly from a phone.

## Model

The phone is the SSH controller. It does not embed the Go installer. Instead it:

1. Builds an install-plan JSON.
2. Builds a secrets env file when sensitive values are needed.
3. Uploads both files to the bridge VPS, for example `/tmp/ultra-plan.json` and `/tmp/ultra-secrets.env`.
3. Runs `deploy/mobile-bootstrap.sh` on the bridge VPS over SSH.
4. Reads `ultra-install` progress from stdout as JSON Lines.

The bridge VPS downloads the official GitHub Release, verifies SHA-256 checksums, installs release binaries under `/opt/ultra/current`, then runs:

```bash
/opt/ultra/current/ultra-install apply-remote \
  -plan /tmp/ultra-plan.json \
  -secrets /tmp/ultra-secrets.env \
  -release-dir /opt/ultra/current \
  -format jsonl
```

`install-plan.json` should not contain secrets. For Telegram bot installs, upload:

```env
TELEGRAM_BOT_TOKEN=...
```

## Release Assets

GitHub releases must contain:

- `ultra-install-linux-amd64`
- `ultra-install-linux-arm64`
- `ultra-relay-linux-amd64`
- `ultra-relay-linux-arm64`
- `ultra-bot-linux-amd64`
- `ultra-bot-linux-arm64`
- `mobile-bootstrap.sh`
- `checksums.txt`
- `checksums.txt.minisig` (recommended for production)
- `release-manifest.json`

Build them locally with:

```bash
make release-dist
```

Tag pushes matching `v*` publish these assets through `.github/workflows/release.yml`.

If the repository secret `MINISIGN_SECRET_KEY` is set, the release workflow signs `checksums.txt` as `checksums.txt.minisig`. Store an unencrypted minisign secret key in that secret and embed the corresponding public key in the mobile app.

## Bootstrap Command

For a pinned release:

```bash
bash /tmp/mobile-bootstrap.sh \
  --repo NikitaDmitryuk/ultra \
  --release vX.Y.Z \
  --plan /tmp/ultra-plan.json \
  --secrets /tmp/ultra-secrets.env \
  --minisign-pubkey 'RWQ...' \
  --require-signature yes \
  --format jsonl
```

For development or manual testing, `--release latest` follows the latest GitHub Release.

The bootstrap script must run as root. The mobile app should either connect as root or perform a one-time key setup step before running the bootstrap.

For development builds without a configured signing key, use `--require-signature no`. Production mobile builds should pin a release tag and require the minisign signature.

If `bot.enabled=true` and no valid secrets env file is provided, `ultra-install` exits with `MISSING_BOT_TOKEN`.

## JSONL Events

Each progress line emitted by `ultra-install -format jsonl` has this shape:

```json
{"time":"2026-06-12T12:00:00Z","kind":"step","code":"","message":"deploying exit 203.0.113.11","node":"primary"}
```

Known `kind` values:

- `step`
- `progress`
- `log`
- `warning`
- `error`

Stable `code` values include:

- `SSH_UNREACHABLE`
- `DNS_MISMATCH`
- `PORT_BLOCKED`
- `MISSING_BOT_TOKEN`
- `REMOTE_PACKAGE_INSTALL_FAILED`
- `NO_EXIT_DEPLOYED`
- `CERTBOT_FAILED`
- `UNSUPPORTED_OS`
- `UNSUPPORTED_ARCH`
- `MISSING_SYSTEMD`
- `GITHUB_UNREACHABLE`

## Remote Doctor

After `ultra-install` is present on a VPS, the app can run:

```bash
/opt/ultra/current/ultra-install doctor-remote -format json
```

This checks the current server as a remote installer host: Linux, amd64/arm64, Debian/Ubuntu signal, systemd, and GitHub egress.
