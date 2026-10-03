# Security

NiceOTP v0.1 is an early, independently implemented project. It has not received
an independent security audit. Please read docs/cryptography.md before entrusting
important accounts to it; retain each service's own recovery options and a tested
portable backup.

Report a suspected vulnerability through this repository's **Security → Report a
vulnerability** private reporting feature. Do not put OTP secrets, passwords,
recovery codes, session tokens or real user data in public issues or logs. If the
private reporting option is unavailable, open a public issue requesting a private
contact without disclosing exploit details or secrets.

The service cannot decrypt user vaults or recover keys lost everywhere. Account
recovery is different from vault recovery. Password changes cannot revoke older
backups or an already copied vault key. Server/identity compromise, malicious
client releases, device malware and weak passwords have distinct threat boundaries;
see the cryptography document for what is and is not protected.
