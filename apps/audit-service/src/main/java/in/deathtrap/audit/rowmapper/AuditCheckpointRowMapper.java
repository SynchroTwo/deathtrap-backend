package in.deathtrap.audit.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a row from audit_hash_checkpoints to an AuditCheckpoint record. */
public class AuditCheckpointRowMapper implements RowMapper<AuditCheckpointRowMapper.AuditCheckpoint> {

    /** Singleton instance for reuse across services. */
    public static final AuditCheckpointRowMapper INSTANCE = new AuditCheckpointRowMapper();

    private AuditCheckpointRowMapper() {}

    @Override
    public AuditCheckpoint mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new AuditCheckpoint(
                rs.getString("checkpoint_id"),
                rs.getString("up_to_audit_id"),
                rs.getString("checkpoint_hash"),
                rs.getTimestamp("created_at").toInstant());
    }

    /** Domain record representing an audit hash checkpoint. */
    public record AuditCheckpoint(
            String checkpointId,
            String upToAuditId,
            String checkpointHash,
            Instant createdAt
    ) {}
}
