-- Slice 13 bugfix: `scan_permits.document_json` was declared JSONB in
-- migration 0005. psycopg3 auto-deserializes a JSONB column into a
-- Python dict on read, but `load_signed_trustscan_permit_json` (the
-- contracts-package loader every backend uses) expects the original
-- JSON string/bytes -- discovered when the production-mode E2E test's
-- permit-issuance round trip crashed reading it back. JSONB also
-- reformats/canonicalizes on storage, which is the wrong storage
-- shape for a signed document in the first place: the exact
-- byte-for-byte JSON representation is not the signature input
-- (signatures are computed over `claims.signing_bytes`, recomputed
-- from the deserialized claims, not compared byte-for-byte), so this
-- was not a signature-verification correctness bug -- but storing a
-- signed artifact as anything other than its own exact text is still
-- the wrong choice on principle, and TEXT is what SQLite's own
-- `scan_permits.document_json` column already uses.
ALTER TABLE scan_permits
    ALTER COLUMN document_json TYPE TEXT USING document_json::text;
