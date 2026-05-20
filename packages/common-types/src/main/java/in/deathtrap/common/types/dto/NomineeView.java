package in.deathtrap.common.types.dto;

/** Wire shape of a nominee record for the A3 creator-side dashboard.
 *  Mirrors the UI's Nominee type (camelCase, short field names).
 *  status is one of: invited | active | removed (lowercase). Path A collapses the
 *  accepted state into 'active' (not 'registered') because recovery-blob eligibility
 *  in StoreBlobHandler and locker nominee assignment require status='active'. The
 *  'registered' enum value remains in the DB type but is unused by the accept flow.
 *  pubkeyPem / pubkeyFingerprint are null until the nominee accepts.
 *  registeredAt is the accept timestamp (DB column registered_at). */
public record NomineeView(
        String nomineeId,
        String creatorId,
        String fullName,
        String email,
        String mobile,
        String status,
        String pubkeyPem,
        String pubkeyFingerprint,
        String invitedAt,
        String registeredAt,
        String removedAt
) {}
