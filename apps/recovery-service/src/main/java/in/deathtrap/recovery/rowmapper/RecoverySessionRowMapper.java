package in.deathtrap.recovery.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps recovery_sessions rows. */
public class RecoverySessionRowMapper implements RowMapper<RecoverySessionRowMapper.RecoverySession> {

    public static final RecoverySessionRowMapper INSTANCE = new RecoverySessionRowMapper();

    private RecoverySessionRowMapper() {}

    @Override
    public RecoverySession mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp initiatedAt = rs.getTimestamp("initiated_at");
        Timestamp lockedUntil = rs.getTimestamp("locked_until");
        Timestamp completedAt = rs.getTimestamp("completed_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new RecoverySession(
                rs.getString("session_id"),
                rs.getString("creator_id"),
                rs.getString("trigger_id"),
                rs.getString("blob_id"),
                rs.getString("status"),
                initiatedAt != null ? initiatedAt.toInstant() : Instant.EPOCH,
                lockedUntil != null ? lockedUntil.toInstant() : Instant.EPOCH,
                completedAt != null ? completedAt.toInstant() : null,
                createdAt != null ? createdAt.toInstant() : Instant.EPOCH);
    }

    /** Domain record for a recovery session. */
    public record RecoverySession(
            String sessionId,
            String creatorId,
            String triggerId,
            String blobId,
            String status,
            Instant initiatedAt,
            Instant lockedUntil,
            Instant completedAt,
            Instant createdAt
    ) {}
}
