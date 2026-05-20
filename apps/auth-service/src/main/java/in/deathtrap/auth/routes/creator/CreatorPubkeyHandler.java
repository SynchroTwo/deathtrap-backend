package in.deathtrap.auth.routes.creator;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.PubkeyView;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public lookup of a creator's active pubkey ({@code GET /auth/creator/{id}/pubkey}).
 *
 * <p>Unauthenticated by design: a nominee fetches this to verify the creator-signed
 * invite token before accepting. Returns SPKI PEM plus the lowercase-hex SHA-256(SPKI DER)
 * fingerprint. The UI converts the PEM to raw SEC1 for its WebCrypto verify step.
 */
@RestController
@RequestMapping("/auth/creator")
public class CreatorPubkeyHandler {

    private static final String SELECT_CREATOR_PUBKEY =
            "SELECT public_key_pem, key_fingerprint FROM party_public_keys " +
            "WHERE party_id = ? AND party_type = 'creator'::party_type_enum AND is_active = true LIMIT 1";

    private static final RowMapper<PubkeyView> PUBKEY_MAPPER = (rs, row) ->
            new PubkeyView(rs.getString("public_key_pem"), rs.getString("key_fingerprint"));

    private final DbClient dbClient;

    /** Constructs CreatorPubkeyHandler with the database client. */
    public CreatorPubkeyHandler(DbClient dbClient) {
        this.dbClient = dbClient;
    }

    /** GET /auth/creator/{id}/pubkey — the creator's active pubkey (public). */
    @GetMapping("/{id}/pubkey")
    public ResponseEntity<ApiResponse<PubkeyView>> pubkey(@PathVariable("id") String creatorId) {
        PubkeyView view = dbClient.queryOne(SELECT_CREATOR_PUBKEY, PUBKEY_MAPPER, creatorId)
                .orElseThrow(() -> AppException.notFound("creator pubkey"));
        return ResponseEntity.ok(ApiResponse.ok(view, UUID.randomUUID().toString()));
    }
}
