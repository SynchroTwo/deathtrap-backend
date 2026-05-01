-- All PostgreSQL enum types for the DeathTrap platform

CREATE TYPE kyc_status_enum AS ENUM ('pending', 'verified', 'failed');
CREATE TYPE user_status_enum AS ENUM ('active', 'suspended', 'deceased', 'deleted');
CREATE TYPE nominee_status_enum AS ENUM ('invited', 'registered', 'active', 'removed');
CREATE TYPE lawyer_status_enum AS ENUM ('pending', 'active', 'suspended', 'removed');
CREATE TYPE party_type_enum AS ENUM ('creator', 'nominee', 'lawyer', 'system', 'admin');
CREATE TYPE otp_channel_enum AS ENUM ('sms', 'email');
CREATE TYPE otp_purpose_enum AS ENUM ('registration', 'login', 'mfa', 'recovery', 'passphrase_change');
CREATE TYPE kyc_type_enum AS ENUM ('aadhaar_otp', 'aadhaar_biometric', 'pan_link', 'bar_council');
CREATE TYPE key_type_enum AS ENUM ('ecdh_p256', 'rsa_oaep_4096');
CREATE TYPE asset_type_enum AS ENUM ('online', 'offline');
CREATE TYPE asset_status_enum AS ENUM ('empty', 'filled', 'skipped');
CREATE TYPE official_nom_status_enum AS ENUM ('unknown', 'pending', 'done');
CREATE TYPE recovery_blob_status_enum AS ENUM ('active', 'superseded', 'invalidated');
CREATE TYPE recovery_session_status_enum AS ENUM ('initiated', 'in_progress', 'completed', 'expired', 'cancelled');
CREATE TYPE trigger_status_enum AS ENUM (
    'pending_threshold', 'threshold_met', 'pending_admin',
    'approved', 'active', 'halted', 'completed', 'cancelled'
);
CREATE TYPE trigger_source_type_enum AS ENUM (
    'death_registry', 'municipality', 'inactivity', 'nominee_report', 'lawyer_report'
);
CREATE TYPE dispute_status_enum AS ENUM (
    'open', 'under_review', 'resolved_proceed', 'resolved_halt', 'withdrawn'
);
CREATE TYPE audit_result_enum AS ENUM ('success', 'failure', 'blocked', 'cancelled');
