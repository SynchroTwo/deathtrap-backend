-- Recovery blobs: one active per creator
CREATE TABLE recovery_blobs (
    blob_id     TEXT                      NOT NULL,
    creator_id  TEXT                      NOT NULL,
    status      recovery_blob_status_enum NOT NULL DEFAULT 'active',
    layer_count INTEGER                   NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ               NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ               NOT NULL DEFAULT NOW(),
    CONSTRAINT recovery_blobs_pkey       PRIMARY KEY (blob_id),
    CONSTRAINT recovery_blobs_creator_fk FOREIGN KEY (creator_id) REFERENCES users (user_id)
);
CREATE UNIQUE INDEX idx_recovery_blobs_active_creator
    ON recovery_blobs (creator_id) WHERE status = 'active';
CREATE TRIGGER trg_recovery_blobs_updated_at
    BEFORE UPDATE ON recovery_blobs FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Recovery blob layers: ordered within a blob
CREATE TABLE recovery_blob_layers (
    layer_id       TEXT        NOT NULL,
    blob_id        TEXT        NOT NULL,
    layer_order    INTEGER     NOT NULL,
    ciphertext_b64 TEXT        NOT NULL,
    nonce_b64      TEXT        NOT NULL,
    auth_tag_b64   TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recovery_blob_layers_pkey      PRIMARY KEY (layer_id),
    CONSTRAINT recovery_blob_layers_blob_fk   FOREIGN KEY (blob_id) REFERENCES recovery_blobs (blob_id),
    CONSTRAINT recovery_blob_layers_order_unq UNIQUE (blob_id, layer_order)
);

-- Recovery sessions
CREATE TABLE recovery_sessions (
    session_id    TEXT                         NOT NULL,
    blob_id       TEXT                         NOT NULL,
    nominee_id    TEXT                         NOT NULL,
    status        recovery_session_status_enum NOT NULL DEFAULT 'initiated',
    layers_peeled INTEGER                      NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ                  NOT NULL,
    created_at    TIMESTAMPTZ                  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ                  NOT NULL DEFAULT NOW(),
    CONSTRAINT recovery_sessions_pkey    PRIMARY KEY (session_id),
    CONSTRAINT recovery_sessions_blob_fk FOREIGN KEY (blob_id)    REFERENCES recovery_blobs (blob_id),
    CONSTRAINT recovery_sessions_nom_fk  FOREIGN KEY (nominee_id) REFERENCES nominees (nominee_id)
);
CREATE TRIGGER trg_recovery_sessions_updated_at
    BEFORE UPDATE ON recovery_sessions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Recovery peel events
CREATE TABLE recovery_peel_events (
    peel_id    TEXT        NOT NULL,
    session_id TEXT        NOT NULL,
    layer_id   TEXT        NOT NULL,
    peeled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT recovery_peel_events_pkey       PRIMARY KEY (peel_id),
    CONSTRAINT recovery_peel_events_session_fk FOREIGN KEY (session_id) REFERENCES recovery_sessions (session_id),
    CONSTRAINT recovery_peel_events_layer_fk   FOREIGN KEY (layer_id)   REFERENCES recovery_blob_layers (layer_id),
    CONSTRAINT recovery_peel_events_unq        UNIQUE (session_id, layer_id)
);

-- Blob rebuild log
CREATE TABLE blob_rebuild_log (
    rebuild_id  TEXT        NOT NULL,
    creator_id  TEXT        NOT NULL,
    old_blob_id TEXT        NOT NULL,
    new_blob_id TEXT        NOT NULL,
    rebuilt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT blob_rebuild_log_pkey PRIMARY KEY (rebuild_id)
);

-- Trigger events: one active trigger per creator at a time
CREATE TABLE trigger_events (
    trigger_id  TEXT                NOT NULL,
    creator_id  TEXT                NOT NULL,
    status      trigger_status_enum NOT NULL DEFAULT 'pending_threshold',
    threshold   INTEGER             NOT NULL DEFAULT 1,
    sources_met INTEGER             NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT trigger_events_pkey       PRIMARY KEY (trigger_id),
    CONSTRAINT trigger_events_creator_fk FOREIGN KEY (creator_id) REFERENCES users (user_id)
);
CREATE UNIQUE INDEX idx_trigger_events_active_creator
    ON trigger_events (creator_id)
    WHERE status IN ('pending_threshold','threshold_met','pending_admin','approved','active');
CREATE TRIGGER trg_trigger_events_updated_at
    BEFORE UPDATE ON trigger_events FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Trigger sources
CREATE TABLE trigger_sources (
    source_id   TEXT                     NOT NULL,
    trigger_id  TEXT                     NOT NULL,
    source_type trigger_source_type_enum NOT NULL,
    received_at TIMESTAMPTZ              NOT NULL DEFAULT NOW(),
    metadata    JSONB,
    CONSTRAINT trigger_sources_pkey       PRIMARY KEY (source_id),
    CONSTRAINT trigger_sources_trigger_fk FOREIGN KEY (trigger_id) REFERENCES trigger_events (trigger_id),
    CONSTRAINT trigger_sources_type_unq   UNIQUE (trigger_id, source_type)
);

-- Inactivity checks
CREATE TABLE inactivity_checks (
    check_id     TEXT        NOT NULL,
    creator_id   TEXT        NOT NULL,
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    response     TEXT,
    CONSTRAINT inactivity_checks_pkey PRIMARY KEY (check_id)
);
CREATE INDEX idx_inactivity_checks_creator ON inactivity_checks (creator_id);

-- Dispute log
CREATE TABLE dispute_log (
    dispute_id  TEXT                NOT NULL,
    trigger_id  TEXT                NOT NULL,
    raised_by   TEXT                NOT NULL,
    raiser_type party_type_enum     NOT NULL,
    status      dispute_status_enum NOT NULL DEFAULT 'open',
    reason      TEXT,
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT dispute_log_pkey       PRIMARY KEY (dispute_id),
    CONSTRAINT dispute_log_trigger_fk FOREIGN KEY (trigger_id) REFERENCES trigger_events (trigger_id)
);
CREATE TRIGGER trg_dispute_log_updated_at
    BEFORE UPDATE ON dispute_log FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Audit log: APPEND ONLY — no updated_at, no update trigger
CREATE TABLE audit_log (
    audit_id       TEXT              NOT NULL,
    event_type     TEXT              NOT NULL,
    actor_id       TEXT,
    actor_type     party_type_enum,
    target_id      TEXT,
    target_type    TEXT,
    session_id     TEXT,
    ip_address     TEXT,
    device_id      TEXT,
    result         audit_result_enum NOT NULL,
    failure_reason TEXT,
    metadata_json  JSONB,
    prev_hash      CHAR(64),
    entry_hash     CHAR(64)          NOT NULL,
    created_at     TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_log_pkey     PRIMARY KEY (audit_id),
    CONSTRAINT audit_log_hash_unq UNIQUE (entry_hash)
);
CREATE INDEX idx_audit_log_actor   ON audit_log (actor_id)   WHERE actor_id  IS NOT NULL;
CREATE INDEX idx_audit_log_target  ON audit_log (target_id)  WHERE target_id IS NOT NULL;
CREATE INDEX idx_audit_log_created ON audit_log (created_at);

-- Audit hash checkpoints
CREATE TABLE audit_hash_checkpoints (
    checkpoint_id   TEXT        NOT NULL,
    up_to_audit_id  TEXT        NOT NULL,
    checkpoint_hash TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_hash_checkpoints_pkey PRIMARY KEY (checkpoint_id)
);
