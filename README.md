# NiceOTP

A self-hostable, end-to-end encrypted TOTP vault with a Rust CLI and a Rust sync
server. **v0.1 is an early release, not independently security audited.**

NiceOTP 是独立开源的 OTP 密钥库。客户端加密、解密和生成验证码；服务器保存密文并处理同步。
用户通过密钥库口令或恢复码解锁，运营者没有代为解密的后台入口。

- Client-side XChaCha20-Poly1305; Argon2id password protection; independent random recovery code.
- Real OIDC browser login with PKCE; authentication is separate from vault unlocking.
- Offline edits, explicit conflicts, idempotent retries, trash and permanent tombstones.
- Authenticated encrypted backups that restore without the original server or device.
- PostgreSQL storage independent from any external identity provider's database.
- macOS and Linux CLI; SHA-1/SHA-256/SHA-512 TOTP, 6 or 8 digits.

## Try it locally

Requires Rust 1.92.0, Docker Compose, and a browser. Development credentials below
are deliberately public; every published port is bound to loopback.

```sh
git clone https://github.com/yiminspace/niceotp.git
cd niceotp
docker compose -f deploy/compose.local.yml up -d
cargo build --locked --workspace
DATABASE_URL='postgres://niceotp:local-development-only@127.0.0.1:55439/niceotp_test' \
OIDC_ISSUER='http://127.0.0.1:5556/dex' OIDC_CLIENT_ID=niceotp-cli \
cargo run --locked -p niceotp-server
```

In another terminal, sign in using `demo@example.test` / `local-development-only`:

```sh
./target/debug/niceotp --data-dir ~/.niceotp-demo login
./target/debug/niceotp --data-dir ~/.niceotp-demo init --recovery-output ~/niceotp-recovery.txt
./target/debug/niceotp --data-dir ~/.niceotp-demo add
./target/debug/niceotp --data-dir ~/.niceotp-demo sync
./target/debug/niceotp --data-dir ~/.niceotp-demo list
./target/debug/niceotp --data-dir ~/.niceotp-demo code ITEM_UUID
```

`init` prompts for a new vault password. `add` prompts for an `otpauth://` URI
without echo; input may also be piped. Keep the recovery file **outside this
profile and preferably off this device**. It is as powerful as the vault password.
Do not put real secrets into shell arguments or shell history.

A second device/profile uses the same login, then `sync`, then the vault password:

```sh
./target/debug/niceotp --data-dir ~/.niceotp-second login
./target/debug/niceotp --data-dir ~/.niceotp-second sync
./target/debug/niceotp --data-dir ~/.niceotp-second list
```

`--server https://otp.example.org` selects a server when creating a profile. Use a
separate `--data-dir` for each server/account. The CLI refuses to mix identities.

## CLI reference

| Command | Behavior |
| --- | --- |
| `login`, `logout` | Browser OIDC login; revoke the current server session on logout |
| `init --recovery-output FILE` | Create the vault and write a new private recovery file |
| `unlock --remember`, `lock` | Save/remove a vault key in macOS Keychain or Linux Secret Service |
| `add`, `import` | Read one URI, or newline-separated URIs, from stdin |
| `list [--trash] [--query TEXT]` | Search decrypted entries locally; no secrets in output |
| `show ID [--reveal]`, `code ID` | Explicitly inspect a secret or generate its TOTP |
| `edit ID --name NAME`, `pin ID [--off]` | Update metadata or pinning |
| `delete ID`, `restore ID` | Move to or restore from the encrypted trash |
| `purge ID --yes` | Permanently delete a trashed entry; sync retains a tombstone |
| `sync` | Upload pending operations in batches and fetch remote changes |
| `conflicts`, `resolve ID --use-version local\|remote` | Inspect both versions and choose explicitly |
| `backup FILE` | Export an authenticated encrypted backup, including pending edits |
| `restore-backup FILE [--recovery-file FILE]` | Offline restore into an empty profile |
| `set-password [--new-password-file FILE]` | Change the vault password, not the login password |
| `recover --recovery-file FILE` | Use a recovery code to set a new vault password |
| `rotate-recovery --output FILE` | Create a replacement recovery wrapper and code |
| `status`, `doctor` | Local sync status and server connectivity/version |

All commands support `--json`; exit status is 0 for success, 1 for runtime errors,
and 2 for invalid arguments. For automation, `--password-file` reads a private
0600 file (also `NICEOTP_PASSWORD_FILE`); passwords are never accepted as direct
command-line values. `login --id-token-file` accepts an already-issued OIDC ID
token for controlled automation; the server applies the same signature, issuer,
audience and expiry checks. It is not an authentication bypass.

Headless Linux systems without a running Secret Service can use password prompts
or private password files. `--remember` fails rather than falling back to a
plaintext key file. An empty vault requires password confirmation because there
is no encrypted entry against which to validate a cached key yet.

## Recovery and portability

```sh
niceotp --data-dir ~/.niceotp-demo backup ~/vault.niceotp
niceotp --data-dir ~/.niceotp-recovered restore-backup ~/vault.niceotp \
  --recovery-file ~/niceotp-recovery.txt
niceotp --data-dir ~/.niceotp-recovered list
```

The restore works offline. It preserves the backup's password/recovery wrappers
and creates fresh item IDs. To publish it, log in to a **fresh account/server**
and run `sync`; it will not overwrite an existing vault. Select the destination
`--server` when first creating the restored profile. Resolve conflicts and
uncertain sync requests before exporting a backup.

Changing the password or recovery code does **not** revoke older backups or
copies of the vault key. If all valid passwords, recovery codes and unlocked
devices are lost, the service cannot decrypt the data. A recovery code also cannot
recreate ciphertext that has been lost everywhere: keep encrypted backups too.

## Deploy and understand

- [Self-hosting and OIDC](docs/self-hosting.md)
- [Architecture and API/sync protocol](docs/protocol.md)
- [Cryptography, threat boundary and interoperability vectors](docs/cryptography.md)
- [v0.1 scope and validation](docs/v0.1.md)
- [Security reporting](SECURITY.md)

This release excludes WeChat integration, graphical clients, HOTP, team sharing,
public hosted registration, legacy data migration and compromised-key rotation.

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
python3 -m venv .local/test-env
.local/test-env/bin/pip install 'cryptography>=44,<50'
TEST_DATABASE_URL='postgres://niceotp:local-development-only@127.0.0.1:55439/niceotp_test' \
  .local/test-env/bin/python scripts/e2e.py
```

`psql` is needed for E2E; override its path with `PSQL`. The script creates and drops its own unique PostgreSQL schema. It
starts a test-only RSA OIDC provider and real server/CLI processes. No real user
credentials or external identity services are needed. CI runs these checks with
PostgreSQL 17 and builds CLI artifacts for macOS/Linux.

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for source provenance.
