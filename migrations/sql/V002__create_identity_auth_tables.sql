-- Trigger function to automatically update updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Users (creators)
CREATE TABLE users (
    user_id                   TEXT             NOT NULL,
    full_name                 TEXT             NOT NULL,
    date_of_birth             DATE             NOT NULL,
    mobile                    TEXT             NOT NULL,
    email                     TEXT             NOT NULL,
    address                   TEXT,
    pan_ref                   TEXT,
    aadhaar_ref               TEXT,
    kyc_status                kyc_status_enum  NOT NULL DEFAULT 'pending',
    status                    user_status_enum NOT NULL DEFAULT 'active',
    risk_accepted_at          TIMESTAMPTZ,
    zero_nominee_risk_version INTEGER,
    locker_completeness_pct   INTEGER          NOT NULL DEFAULT 0,
    last_reviewed_at          TIMESTAMPTZ,
    inactivity_trigger_months INTEGER          NOT NULL,
    created_at                TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    deleted_at                TIMESTAMPTZ,
    CONSTRAINT users_pkey           PRIMARY KEY (user_id),
    CONSTRAINT users_locker_pct_chk CHECK (locker_completeness_pct BETWEEN 0 AND 100),
    CONSTRAINT users_inactivity_chk CHECK (inactivity_trigger_months IN (6, 12, 24, 36))
);
CREATE UNIQUE INDEX idx_users_mobile ON users (mobile) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_email  ON users (email)  WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users (status) WHERE deleted_at IS NULL;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Nominees
CREATE TABLE nominees (
    nominee_id              TEXT                NOT NULL,
    creator_id              TEXT                NOT NULL,
    full_name               TEXT                NOT NULL,
    mobile                  TEXT                NOT NULL,
    email                   TEXT                NOT NULL,
    relationship            TEXT                NOT NULL,
    registration_order      INTEGER             NOT NULL DEFAULT 0,
    invite_token_hash       TEXT,
    invite_expires_at       TIMESTAMPTZ,
    status                  nominee_status_enum NOT NULL DEFAULT 'invited',
    fingerprint_verified    BOOLEAN             NOT NULL DEFAULT FALSE,
    fingerprint_verified_at TIMESTAMPTZ,
    created_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT nominees_pkey      PRIMARY KEY (nominee_id),
    CONSTRAINT nominees_creator_fk FOREIGN KEY (creator_id) REFERENCES users (user_id)
);
CREATE INDEX idx_nominees_creator_status ON nominees (creator_id, status);
CREATE INDEX idx_nominees_invite_token   ON nominees (invite_token_hash)
    WHERE invite_token_hash IS NOT NULL;
CREATE TRIGGER trg_nominees_updated_at
    BEFORE UPDATE ON nominees FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Lawyers
CREATE TABLE lawyers (
    lawyer_id          TEXT               NOT NULL,
    full_name          TEXT               NOT NULL,
    mobile             TEXT               NOT NULL,
    email              TEXT               NOT NULL,
    bar_council        TEXT               NOT NULL,
    enrollment_no      TEXT               NOT NULL,
    bar_verified       BOOLEAN            NOT NULL DEFAULT FALSE,
    bar_verified_at    TIMESTAMPTZ,
    status             lawyer_status_enum NOT NULL DEFAULT 'pending',
    kyc_admin_approved BOOLEAN            NOT NULL DEFAULT FALSE,
    kyc_approved_at    TIMESTAMPTZ,
    created_at         TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    CONSTRAINT lawyers_pkey   PRIMARY KEY (lawyer_id),
    CONSTRAINT lawyers_mobile UNIQUE (mobile),
    CONSTRAINT lawyers_email  UNIQUE (email)
);
CREATE TRIGGER trg_lawyers_updated_at
    BEFORE UPDATE ON lawyers FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Sessions (polymorphic across creator / nominee / lawyer)
CREATE TABLE sessions (
    session_id         TEXT            NOT NULL,
    party_id           TEXT            NOT NULL,
    party_type         party_type_enum NOT NULL,
    jwt_jti            TEXT            NOT NULL,
    device_fingerprint TEXT,
    ip_address         TEXT,
    user_agent         TEXT,
    expires_at         TIMESTAMPTZ     NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT sessions_pkey    PRIMARY KEY (session_id),
    CONSTRAINT sessions_jti_unq UNIQUE (jwt_jti)
);
CREATE INDEX idx_sessions_party ON sessions (party_id, party_type, revoked_at);
CREATE INDEX idx_sessions_jti   ON sessions (jwt_jti);

-- OTP log — stores BCrypt hash only, never plaintext OTP
CREATE TABLE otp_log (
    otp_id       TEXT             NOT NULL,
    party_id     TEXT             NOT NULL,
    party_type   party_type_enum  NOT NULL,
    channel      otp_channel_enum NOT NULL,
    purpose      otp_purpose_enum NOT NULL,
    otp_hash     TEXT             NOT NULL,
    attempts     INTEGER          NOT NULL DEFAULT 0,
    verified     BOOLEAN          NOT NULL DEFAULT FALSE,
    locked_until TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ      NOT NULL,
    created_at   TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    CONSTRAINT otp_log_pkey PRIMARY KEY (otp_id)
);
CREATE INDEX idx_otp_log_party ON otp_log (party_id, party_type, purpose, created_at DESC);

-- KYC flags: individual check results per party
CREATE TABLE kyc_flags (
    kyc_id     TEXT            NOT NULL,
    party_id   TEXT            NOT NULL,
    party_type party_type_enum NOT NULL,
    kyc_type   kyc_type_enum   NOT NULL,
    passed     BOOLEAN         NOT NULL DEFAULT FALSE,
    checked_at TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    metadata   JSONB,
    CONSTRAINT kyc_flags_pkey PRIMARY KEY (kyc_id)
);
CREATE INDEX idx_kyc_flags_party ON kyc_flags (party_id, party_type);
