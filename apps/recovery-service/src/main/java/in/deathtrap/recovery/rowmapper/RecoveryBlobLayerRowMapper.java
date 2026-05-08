package in.deathtrap.recovery.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps recovery_blob_layers rows. */
public class RecoveryBlobLayerRowMapper implements RowMapper<RecoveryBlobLayerRowMapper.RecoveryBlobLayer> {

    public static final RecoveryBlobLayerRowMapper INSTANCE = new RecoveryBlobLayerRowMapper();

    private RecoveryBlobLayerRowMapper() {}

    @Override
    public RecoveryBlobLayer mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new RecoveryBlobLayer(
                rs.getString("layer_id"),
                rs.getString("blob_id"),
                rs.getInt("layer_order"),
                rs.getString("party_id"),
                rs.getString("party_type"),
                rs.getString("pubkey_id"),
                rs.getString("key_fingerprint"),
                createdAt != null ? createdAt.toInstant() : Instant.EPOCH);
    }

    /** Domain record for a recovery blob layer. */
    public record RecoveryBlobLayer(
            String layerId,
            String blobId,
            int layerOrder,
            String partyId,
            String partyType,
            String pubkeyId,
            String keyFingerprint,
            Instant createdAt
    ) {}
}
