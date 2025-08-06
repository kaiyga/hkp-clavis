-- Table for PGP keys
CREATE TABLE IF NOT EXISTS pgp_keys (
    fingerprint             VARCHAR(64) PRIMARY KEY, 
    packet                  TEXT NOT NULL,           -- Armored public key block
    revoked                 BOOLEAN NOT NULL DEFAULT FALSE,  
    update_time             TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pgp_keys_fingerprint ON pgp_keys (fingerprint);


-- Table for User IDs associated with PGP keys
CREATE TABLE IF NOT EXISTS pgp_uids (
    fingerprint         VARCHAR(64) NOT NULL,    -- Foreign key to pgp_keys.fingerprint
    uid                     TEXT NOT NULL,           -- Full User ID string (e.g., "Full Name (Comment) <email>")
    email                   TEXT NOT NULL,           
    verified                BOOLEAN NOT NULL DEFAULT FALSE, 
    verification_token      TEXT UNIQUE,            -- Token for email verification
    token_expires_at        TIMESTAMP WITH TIME ZONE, -- Token expiry timestamp

    UNIQUE (fingerprint, uid), -- Ensures unique User ID for a given key

    CONSTRAINT fk_pgp_uids_fingerprint
        FOREIGN KEY (fingerprint)
        REFERENCES pgp_keys (fingerprint)
        ON DELETE CASCADE 
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_pgp_uids_email ON pgp_uids (email);
CREATE INDEX IF NOT EXISTS idx_pgp_uids_verified ON pgp_uids (verified);

-- For advanced text search on 'uid' (user_id_string) using LIKE or regex, consider pg_trgm.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX  IF NOT EXISTS idx_pgp_uids_uid_gin ON pgp_uids USING GIN (uid gin_trgm_ops);
