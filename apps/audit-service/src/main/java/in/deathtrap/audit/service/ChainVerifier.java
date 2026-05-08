package in.deathtrap.audit.service;

import in.deathtrap.audit.rowmapper.AuditLogRowMapper;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Verifies the SHA-256 hash chain integrity of the audit_log table.
 * Re-computes entry_hash for each row using the same formula as AuditWriter and
 * compares it to the stored value, stopping at the first mismatch.
 */
@Service
public class ChainVerifier {

    private static final Logger log = LoggerFactory.getLogger(ChainVerifier.class);

    private static final String SELECT_ALL =
            "SELECT * FROM audit_log ORDER BY created_at ASC, audit_id ASC";
    private static final String SELECT_FROM =
            "SELECT * FROM audit_log WHERE created_at >= " +
            "(SELECT created_at FROM audit_log WHERE audit_id = ?) " +
            "ORDER BY created_at ASC, audit_id ASC";

    private final DbClient db;

    /** Constructs ChainVerifier with required DbClient. */
    public ChainVerifier(DbClient db) {
        this.db = db;
    }

    /**
     * Verifies the hash chain integrity starting from the given audit entry.
     * If fromAuditId is null, verification starts from the genesis entry.
     * Returns on first mismatch to avoid unnecessary full-table scans.
     */
    public ChainVerifyResult verify(String fromAuditId) {
        List<AuditLogRow> entries = fromAuditId == null
                ? db.query(SELECT_ALL, AuditLogRowMapper.INSTANCE)
                : db.query(SELECT_FROM, AuditLogRowMapper.INSTANCE, fromAuditId);

        if (entries.isEmpty()) {
            return new ChainVerifyResult(true, 0, null, Instant.now(), Instant.now());
        }

        // Hash chain formula (must match AuditWriter exactly):
        // SHA256(prevHash + auditId + eventType + actorId + targetId + result + createdAt)
        String prevHash = "";
        for (int i = 0; i < entries.size(); i++) {
            AuditLogRow entry = entries.get(i);
            String expected = Sha256Util.hashHex(
                    prevHash
                    + entry.auditId()
                    + entry.eventType()
                    + (entry.actorId() != null ? entry.actorId() : "")
                    + (entry.targetId() != null ? entry.targetId() : "")
                    + entry.result()
                    + entry.createdAt().toString());

            if (!expected.equals(entry.entryHash())) {
                log.error("Audit chain integrity failure at auditId={}", entry.auditId());
                return new ChainVerifyResult(false, i + 1, entry.auditId(),
                        entries.get(0).createdAt(), entry.createdAt());
            }
            prevHash = entry.entryHash();
        }

        return new ChainVerifyResult(true, entries.size(), null,
                entries.get(0).createdAt(),
                entries.get(entries.size() - 1).createdAt());
    }

    /** Result of a hash chain verification run. */
    public record ChainVerifyResult(
            boolean valid,
            int entriesChecked,
            String firstInvalidAuditId,
            Instant verifiedFrom,
            Instant verifiedTo
    ) {}
}
