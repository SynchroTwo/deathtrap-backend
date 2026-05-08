package in.deathtrap.locker.rowmapper;

import in.deathtrap.common.types.domain.LockerMeta;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.jdbc.core.RowMapper;

/** Maps a locker_meta result row to a LockerMeta domain record. */
public class LockerMetaRowMapper implements RowMapper<LockerMeta> {

    public static final LockerMetaRowMapper INSTANCE = new LockerMetaRowMapper();

    @Override
    public LockerMeta mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new LockerMeta(
                rs.getString("locker_id"),
                rs.getString("user_id"),
                rs.getInt("completeness_pct"),
                rs.getInt("online_pct"),
                rs.getInt("offline_pct"),
                rs.getBoolean("blob_built"),
                rs.getTimestamp("last_saved_at") != null ? rs.getTimestamp("last_saved_at").toInstant() : null,
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant());
    }
}
