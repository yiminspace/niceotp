# Contributing

Read AGENTS.md and the protocol/cryptography documents before changing behavior.
Keep server and client dependencies separate: the server cannot decrypt vaults.
Changes to the wire or backup format require a compatibility decision, versioned
fixtures and recovery tests. Do not include code or assets without permission to
redistribute them under compatible terms. Submit only synthetic test data.

Run the README development checks, including PostgreSQL E2E for storage, HTTP,
authentication or synchronization changes. GUI and legacy migration work are out
of scope for v0.1. Open an issue to discuss protocol or cryptographic changes
before implementing them.
