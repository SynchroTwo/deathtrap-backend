package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.PeelRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoveryPeelEventRowMapper.RecoveryPeelEvent;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.support.TransactionCallback;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Sprint A6 B-A6-1 tests: peel ciphertext relay + session-status currentEncryptedB64 routing. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class RecoveryRelayTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private PeelHandler peelHandler;
    @InjectMocks private GetSessionStatusHandler statusHandler;

    private static final String BEARER = "Bearer jwt";
    private static final String SESSION_ID = "session-1";
    private static final String INTERMEDIATE_B64 =
            Base64.getEncoder().encodeToString("peeler-1-output".getBytes());

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoverySession inProgressSession() {
        return new RecoverySession(SESSION_ID, "creator-1", "trigger-1", "blob-1",
                "in_progress", Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(3600), null, Instant.now());
    }

    private RecoveryBlobLayer layer1() {
        return new RecoveryBlobLayer("layer-1", "blob-1", 1,
                "nominee-1", "nominee", "pubkey-1", "a".repeat(64), Instant.now());
    }

    private RecoveryBlobLayer layer2() {
        return new RecoveryBlobLayer("layer-2", "blob-1", 2,
                "lawyer-1", "lawyer", "pubkey-2", "b".repeat(64), Instant.now());
    }

    private RecoveryPeelEvent peelEvent() {
        return new RecoveryPeelEvent("peel-1", SESSION_ID, "layer-1", "nominee-1",
                "nominee", 1, "h".repeat(64), Instant.now(), Instant.now());
    }

    // ── B-A6-1.1: peel persists the relayed ciphertext ──────────────────────

    @Test
    void peel_persistsIntermediateCiphertext() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                 // 1-vararg
                .thenReturn((List) List.of(inProgressSession()))        // SELECT_SESSION
                .thenReturn((List) List.of(0))                          // SELECT_MAX_PEELED
                .thenReturn((List) List.of(2))                          // SELECT_LAYER_COUNT (in txn)
                .thenReturn((List) List.of(1));                         // SELECT_PEEL_COUNT (in txn)
        when(dbClient.query(anyString(), any(), any(), any(), any()))   // 3-vararg
                .thenReturn((List) List.of(layer1()))                   // SELECT_MY_LAYER
                .thenReturn((List) Collections.emptyList());            // SELECT_ALREADY_PEELED
        when(dbClient.queryOne(anyString(), any(), any()))              // SELECT_BLOB_SPEC_VERSION
                .thenReturn(Optional.of("v1"));
        when(dbClient.query(anyString(), any(), any(), any()))          // 2-vararg SELECT_NEXT_PARTY
                .thenReturn((List) List.of(layer2()));
        when(dbClient.withTransaction(any())).thenAnswer(inv ->
                inv.getArgument(0, TransactionCallback.class).doInTransaction(null));

        ResponseEntity<?> response = peelHandler.peel(
                SESSION_ID, new PeelRequest(INTERMEDIATE_B64, null), BEARER);

        assertEquals(200, response.getStatusCode().value());

        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(dbClient).execute(
                argThat(sql -> sql != null && sql.contains("intermediate_ciphertext_b64")),
                args.capture());
        assertTrue(Arrays.asList(args.getValue()).contains(INTERMEDIATE_B64),
                "the submitted ciphertext must be persisted for the next peeler");
    }

    // ── B-A6-1.2: session-status serves the right currentEncryptedB64 source ─

    @Test
    void sessionStatus_beforeAnyPeel_doesNotQueryIntermediate() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))                 // 1-vararg
                .thenReturn((List) List.of(inProgressSession()))        // SELECT_SESSION
                .thenReturn((List) Collections.emptyList())             // SELECT_PEEL_EVENTS (0 peeled)
                .thenReturn((List) List.of(2))                          // SELECT_LAYER_COUNT
                .thenReturn((List) Collections.emptyList());            // SELECT_LAYERS
        when(dbClient.query(anyString(), any(), any(), any()))          // 2-vararg SELECT_NEXT_PARTY
                .thenReturn((List) List.of(layer1()));

        ResponseEntity<?> response = statusHandler.getStatus(SESSION_ID, BEARER);

        assertEquals(200, response.getStatusCode().value());
        // layer 1 source is the blob envelope (salt_hex relay), never the intermediate
        verify(dbClient).queryOne(argThat(sql -> sql != null && sql.contains("salt_hex")), any(), any());
        verify(dbClient, never()).queryOne(
                argThat(sql -> sql != null && sql.contains("intermediate_ciphertext_b64")), any(), any());
    }

    @Test
    void sessionStatus_afterPeel_queriesLatestIntermediate() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))                 // 1-vararg
                .thenReturn((List) List.of(inProgressSession()))        // SELECT_SESSION
                .thenReturn((List) List.of(peelEvent()))                // SELECT_PEEL_EVENTS (1 peeled)
                .thenReturn((List) List.of(2))                          // SELECT_LAYER_COUNT
                .thenReturn((List) Collections.emptyList());            // SELECT_LAYERS
        when(dbClient.query(anyString(), any(), any(), any()))          // 2-vararg SELECT_NEXT_PARTY
                .thenReturn((List) List.of(layer2()));
        when(dbClient.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.empty())                           // SELECT_BLOB_RELAY
                .thenReturn(Optional.of(INTERMEDIATE_B64));             // SELECT_LATEST_INTERMEDIATE

        ResponseEntity<?> response = statusHandler.getStatus(SESSION_ID, BEARER);

        assertEquals(200, response.getStatusCode().value());
        verify(dbClient).queryOne(
                argThat(sql -> sql != null && sql.contains("intermediate_ciphertext_b64")), any(), any());
    }
}
