package in.deathtrap.locker.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps an asset_index result row to an AssetIndex record. */
public class AssetIndexRowMapper implements RowMapper<AssetIndexRowMapper.AssetIndex> {

    public static final AssetIndexRowMapper INSTANCE = new AssetIndexRowMapper();

    @Override
    public AssetIndex mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new AssetIndex(
                rs.getString("asset_id"),
                rs.getString("locker_id"),
                rs.getString("category_code"),
                rs.getString("asset_type"),
                rs.getString("status"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant());
    }

    /** Immutable snapshot of an asset_index row. */
    public record AssetIndex(
            String assetId,
            String lockerId,
            String categoryCode,
            String assetType,
            String status,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
