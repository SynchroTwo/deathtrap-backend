package in.deathtrap.recovery.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps recovery_blobs rows. */
public class RecoveryBlobRowMapper implements RowMapper<RecoveryBlobRowMapper.RecoveryBlob> {

    public static final RecoveryBlobRowMapper INSTANCE = new RecoveryBlobRowMapper();

    private RecoveryBlobRowMapper() {}

    @Override
    public RecoveryBlob mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp builtAt = rs.getTimestamp("built_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new RecoveryBlob(
                rs.getString("blob_id"),
                rs.getString("creator_id"),
                rs.getString("s3_key"),
                rs.getInt("layer_count"),
                rs.getString("status"),
                builtAt != null ? builtAt.toInstant() : Instant.EPOCH,
                createdAt != null ? createdAt.toInstant() : Instant.EPOCH);
    }

    /** Domain record for a recovery blob. */
    public record RecoveryBlob(
            String blobId,
            String creatorId,
            String s3Key,
            int layerCount,
            String status,
            Instant builtAt,
            Instant createdAt
    ) {}
}
