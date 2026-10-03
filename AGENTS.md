# NiceOTP implementation rules

This is an independently implemented public project. Use this repository's requirements,
public standards and publicly licensed dependencies only. Do not consult, copy, translate,
or adapt proprietary repositories, internal documentation, infrastructure or test data.

- User-owned encryption: servers never receive vault passwords, recovery keys, plaintext
  entries or unwrapped vault keys. No request/response body or credential logging.
- Authentication and vault unlocking are separate. No authentication bypass in the server.
- Server changes are transactional, scoped by authenticated owner, versioned and idempotent.
- Permanent deletion keeps a tombstone; stale clients cannot recreate that item ID.
- Local persistent entry data, including pending changes, must be encrypted.
- Public protocol changes require tests and documentation. No custom cryptographic primitives.
- Test actual HTTP and PostgreSQL behavior, including errors, recovery and concurrent clients.
- Never commit credentials, real OTP secrets, user data or environment-specific settings.
- Run cargo fmt, cargo clippy --workspace --all-targets -- -D warnings, and cargo test --workspace.

