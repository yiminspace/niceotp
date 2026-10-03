# Self-hosting

## Deployment

The production Compose file runs PostgreSQL and the server. An existing OIDC
identity provider is required; the local Dex demo is not a production provider.

1. Register a **public native client**, ID `niceotp-cli`, at your OIDC provider.
2. Enable authorization-code flow with S256 PKCE and the `openid email` scopes.
3. Register exactly `http://127.0.0.1:43673/callback` as the loopback redirect.
4. Use RS256 ID tokens, the configured issuer URL and this client's audience.
5. Copy `.env.example` to `.env`, generate a random **hex** PostgreSQL password,
   and set `OIDC_ISSUER` to your provider's HTTPS issuer URL.
6. Run `docker compose up -d --build`.
7. Put your HTTPS reverse proxy in front of `127.0.0.1:8080`. Do not expose PostgreSQL.

OIDC issuer/subject pairs are mapped to local accounts. Changing provider or
subject changes identity; keep a portable backup when moving identity systems.
Only identities admitted by your provider should be able to obtain ID tokens for
this client. Each session lasts 30 days and can be revoked by `logout`; at most
50 active sessions per account are admitted. The provider controls login/account
recovery; it cannot reset the vault encryption password.

The CLI and server reject cleartext remote URLs. Loopback HTTP is allowed for
local development. `ALLOW_INSECURE_OIDC=true` exists only for isolated development
networks; do not set it in production. Discovery uses the configured issuer only,
redirects are disabled, and JWKS is refreshed after five minutes. Plan provider
key rotation with overlapping old/new signing keys.

## Configuration

| Variable | Required/default |
| --- | --- |
| `DATABASE_URL` | Required PostgreSQL URL; use a dedicated NiceOTP DB and role |
| `OIDC_ISSUER` | Required exact issuer URL |
| `OIDC_CLIENT_ID` | Required public native client ID |
| `LISTEN_ADDR` | `127.0.0.1:8080` (container: `0.0.0.0:8080`) |
| `ALLOW_INSECURE_OIDC` | Absent/false; development-only override |

Migrations run before serving requests. The database role must own its schema;
create a dedicated database/role, never reuse an authentication database. The
server runs as a non-root user in its container. `/health` returns the package
version; `/ready` checks the database. HTTP drains on SIGTERM. Logs include route
templates, status and duration only, not raw URLs, request bodies or credentials.

## Backups and limitations

Back up the PostgreSQL volume/database using your normal encrypted backup system,
and test restoration. Server-side backup is not a replacement for the user's
portable vault backup. Operators can restore ciphertext and account/session rows;
they cannot restore missing user keys. Treat identity metadata and session hashes
as sensitive even though vault contents are encrypted.

v0.1 bounds each sync batch to 128 mutations, each encrypted entry to 16 KiB
plaintext plus AEAD tag, and each vault to **1,000 item IDs including permanent
tombstones**. Tombstones and mutation receipts are retained; automatic history
compaction is not implemented. These limits keep full delta responses and portable
backups bounded. CLI `import` and restored backups are synchronized in batches.

This early release does not include public registration abuse controls, account
administration/deletion, operational quotas/billing, independent security audit or
compromised-key rotation. Deploy behind a controlled identity provider for early
self-hosted use; do not advertise it as an audited public credential service.

## Local demonstration

`deploy/compose.local.yml` binds a temporary PostgreSQL and Dex to loopback. Run
the Rust server on the host, as documented in README, so the browser and server
use the same issuer URL. The demo login is `demo@example.test` with password
`local-development-only`. Dex uses in-memory state; this is intentionally a demo.
Shut it down with `docker compose -f deploy/compose.local.yml down`.
