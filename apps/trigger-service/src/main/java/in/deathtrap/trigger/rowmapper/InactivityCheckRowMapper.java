package in.deathtrap.trigger.rowmapper;

import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a row from inactivity_checks to an InactivityCheck record. */
public class InactivityCheckRowMapper implements RowMapper<InactivityCheckRowMapper.InactivityCheck> {

    /** Singleton instance for reuse across handlers and services. */
    public static final InactivityCheckRowMapper INSTANCE = new InactivityCheckRowMapper();

    private InactivityCheckRowMapper() {}

    @Override
    public InactivityCheck mapRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        Timestamp lastCheckinAt = rs.getTimestamp("last_checkin_at");
        Timestamp nextCheckAt = rs.getTimestamp("next_check_at");
        return new InactivityCheck(
                rs.getString("check_id"),
                rs.getString("creator_id"),
                lastCheckinAt != null ? lastCheckinAt.toInstant() : null,
                nextCheckAt != null ? nextCheckAt.toInstant() : null,
                rs.getInt("alerts_sent"),
                rs.getBoolean("triggered"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant());
    }

    /** Domain record representing an inactivity check row. */
    public record InactivityCheck(
            String checkId,
            String creatorId,
            Instant lastCheckinAt,
            Instant nextCheckAt,
            int alertsSent,
            boolean triggered,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
