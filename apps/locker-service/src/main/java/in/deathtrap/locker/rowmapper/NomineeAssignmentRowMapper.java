package in.deathtrap.locker.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a nominee_assignments result row to a NomineeAssignment record. */
public class NomineeAssignmentRowMapper implements RowMapper<NomineeAssignmentRowMapper.NomineeAssignment> {

    public static final NomineeAssignmentRowMapper INSTANCE = new NomineeAssignmentRowMapper();

    @Override
    public NomineeAssignment mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new NomineeAssignment(
                rs.getString("assignment_id"),
                rs.getString("asset_id"),
                rs.getString("locker_id"),
                rs.getString("nominee_id"),
                rs.getString("official_nomination_status"),
                rs.getInt("display_order"),
                rs.getString("notes"),
                rs.getTimestamp("assigned_at").toInstant(),
                rs.getTimestamp("removed_at") != null ? rs.getTimestamp("removed_at").toInstant() : null,
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null);
    }

    /** Immutable snapshot of a nominee_assignments row. */
    public record NomineeAssignment(
            String assignmentId,
            String assetId,
            String lockerId,
            String nomineeId,
            String officialNominationStatus,
            int displayOrder,
            String notes,
            Instant assignedAt,
            Instant removedAt,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
