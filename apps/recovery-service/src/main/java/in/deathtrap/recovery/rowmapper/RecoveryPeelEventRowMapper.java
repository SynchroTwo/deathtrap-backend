package in.deathtrap.recovery.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps recovery_peel_events rows. */
public class RecoveryPeelEventRowMapper implements RowMapper<RecoveryPeelEventRowMapper.RecoveryPeelEvent> {

    public static final RecoveryPeelEventRowMapper INSTANCE = new RecoveryPeelEventRowMapper();

    private RecoveryPeelEventRowMapper() {}

    @Override
    public RecoveryPeelEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp peeledAt = rs.getTimestamp("peeled_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new RecoveryPeelEvent(
                rs.getString("peel_id"),
                rs.getString("session_id"),
                rs.getString("layer_id"),
                rs.getString("party_id"),
                rs.getString("party_type"),
                rs.getInt("layer_order"),
                rs.getString("intermediate_hash"),
                peeledAt != null ? peeledAt.toInstant() : Instant.EPOCH,
                createdAt != null ? createdAt.toInstant() : Instant.EPOCH);
    }

    /** Domain record for a peel event. */
    public record RecoveryPeelEvent(
            String peelId,
            String sessionId,
            String layerId,
            String partyId,
            String partyType,
            int layerOrder,
            String intermediateHash,
            Instant peeledAt,
            Instant createdAt
    ) {}
}
