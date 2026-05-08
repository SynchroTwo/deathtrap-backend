package in.deathtrap.locker.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a blob_versions result row to a BlobVersion record. */
public class BlobVersionRowMapper implements RowMapper<BlobVersionRowMapper.BlobVersion> {

    public static final BlobVersionRowMapper INSTANCE = new BlobVersionRowMapper();

    @Override
    public BlobVersion mapRow(ResultSet rs, int rowNum) throws SQLException {
        long rawSize = rs.getLong("size_bytes");
        Long sizeBytes = rs.wasNull() ? null : rawSize;
        return new BlobVersion(
                rs.getString("blob_id"),
                rs.getString("asset_id"),
                rs.getString("locker_id"),
                rs.getString("s3_key"),
                sizeBytes,
                rs.getString("content_hash_sha256"),
                rs.getInt("schema_version"),
                rs.getBoolean("is_current"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null);
    }

    /** Immutable snapshot of a blob_versions row. */
    public record BlobVersion(
            String blobId,
            String assetId,
            String lockerId,
            String s3Key,
            Long sizeBytes,
            String contentHashSha256,
            int schemaVersion,
            boolean isCurrent,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
