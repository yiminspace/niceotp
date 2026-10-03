-- Keep idempotency without retaining historical entry ciphertext in receipts.
-- PostgreSQL's SHA-256 builtin needs no extension or additional privilege.
ALTER TABLE mutations ADD COLUMN request_hash TEXT;
UPDATE mutations SET request_hash = encode(sha256(convert_to(request::text, 'UTF8')), 'hex');
ALTER TABLE mutations ALTER COLUMN request_hash SET NOT NULL;
ALTER TABLE mutations DROP COLUMN request;
