package in.deathtrap.sqsconsumer.rowmapper;

import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a row from trigger_events to a TriggerEvent record. */
public class TriggerEventRowMapper implements RowMapper<TriggerEventRowMapper.TriggerEvent> {

    /** Singleton instance for reuse across services. */
    public static final TriggerEventRowMapper INSTANCE = new TriggerEventRowMapper();

    private TriggerEventRowMapper() {}

    @Override
    public TriggerEvent mapRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        Timestamp thresholdMetAt = rs.getTimestamp("threshold_met_at");
        return new TriggerEvent(
                rs.getString("trigger_id"),
                rs.getString("creator_id"),
                rs.getString("status"),
                rs.getBoolean("threshold_met"),
                thresholdMetAt != null ? thresholdMetAt.toInstant() : null,
                rs.getTimestamp("created_at").toInstant());
    }

    /** Domain record representing a trigger event. */
    public record TriggerEvent(
            String triggerId,
            String creatorId,
            String status,
            boolean thresholdMet,
            Instant thresholdMetAt,
            Instant createdAt
    ) {}
}
