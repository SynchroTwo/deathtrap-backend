package in.deathtrap.sqsconsumer.rowmapper;

import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a row from trigger_sources to a TriggerSource record. */
public class TriggerSourceRowMapper implements RowMapper<TriggerSourceRowMapper.TriggerSource> {

    /** Singleton instance for reuse across services. */
    public static final TriggerSourceRowMapper INSTANCE = new TriggerSourceRowMapper();

    private TriggerSourceRowMapper() {}

    @Override
    public TriggerSource mapRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        return new TriggerSource(
                rs.getString("source_id"),
                rs.getString("trigger_id"),
                rs.getString("source_type"),
                rs.getString("reference_id"),
                rs.getBoolean("verified"),
                rs.getTimestamp("received_at").toInstant(),
                rs.getTimestamp("created_at").toInstant());
    }

    /** Domain record representing a trigger source confirmation. */
    public record TriggerSource(
            String sourceId,
            String triggerId,
            String sourceType,
            String referenceId,
            boolean verified,
            Instant receivedAt,
            Instant createdAt
    ) {}
}
