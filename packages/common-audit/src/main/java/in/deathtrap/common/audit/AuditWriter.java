package in.deathtrap.common.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/** Appends tamper-evident entries to the append-only audit_log table. */
@Component
public class AuditWriter {

    private static final Logger log = LoggerFactory.getLogger(AuditWriter.class);

    private static final String SELECT_PREV_HASH =
            "SELECT entry_hash FROM audit_log ORDER BY created_at DESC LIMIT 1";

    private static final String INSERT_AUDIT =
            "INSERT INTO audit_log (audit_id, event_type, actor_id, actor_type, target_id, " +
            "target_type, session_id, ip_address, device_id, result, failure_reason, " +
            "metadata_json, prev_hash, entry_hash, created_at) " +
            "VALUES (?, ?::text, ?, ?::party_type_enum, ?, ?, ?, ?, ?, ?::audit_result_enum, ?, ?::jsonb, ?, ?, ?)";

    private static final RowMapper<String> STRING_MAPPER = (rs, rowNum) -> rs.getString(1);

    private final DbClient dbClient;
    private final ObjectMapper objectMapper;

    /** Constructs AuditWriter with the given DbClient. */
    public AuditWriter(DbClient dbClient) {
        this.dbClient = dbClient;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Writes an audit log entry. Failures are logged but never propagate —
     * audit failure must not block the main operation.
     *
     * @param payload the audit event to record
     */
    public void write(AuditWritePayload payload) {
        try {
            String auditId = CsprngUtil.randomUlid();
            Instant now = Instant.now();

            Optional<String> prevHashOpt = dbClient.queryOne(SELECT_PREV_HASH, STRING_MAPPER);
            String prevHash = prevHashOpt.orElse(null);

            String hashInput = (prevHash != null ? prevHash : "")
                    + auditId
                    + payload.eventType().name()
                    + (payload.actorId() != null ? payload.actorId() : "")
                    + (payload.targetId() != null ? payload.targetId() : "")
                    + payload.result().name()
                    + now;

            String entryHash = Sha256Util.hashHex(hashInput);

            String metadataJsonStr = null;
            if (payload.metadataJson() != null && !payload.metadataJson().isEmpty()) {
                try {
                    metadataJsonStr = objectMapper.writeValueAsString(payload.metadataJson());
                } catch (JsonProcessingException e) {
                    log.warn("Failed to serialize audit metadata, omitting");
                }
            }

            dbClient.execute(INSERT_AUDIT,
                    auditId,
                    payload.eventType().name(),
                    payload.actorId(),
                    payload.actorType() != null ? payload.actorType().name().toLowerCase() : null,
                    payload.targetId(),
                    payload.targetType(),
                    payload.sessionId(),
                    payload.ipAddress(),
                    payload.deviceId(),
                    payload.result().name().toLowerCase(),
                    payload.failureReason(),
                    metadataJsonStr,
                    prevHash,
                    entryHash,
                    now);

        } catch (Exception ex) {
            log.error("Audit write failed — event={} result={}", payload.eventType(), payload.result(), ex);
            // Intentionally not re-throwing: audit failure must never block the main operation
        }
    }
}
