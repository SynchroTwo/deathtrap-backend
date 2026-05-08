package in.deathtrap.audit.service;

import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.ChainVerifier.ChainVerifyResult;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for ChainVerifier — pure logic, no Spring context. */
@ExtendWith(MockitoExtension.class)
class ChainVerifierTest {

    @Mock private DbClient db;
    @InjectMocks private ChainVerifier verifier;

    private static final Instant T1 = Instant.parse("2026-05-08T10:00:00.000000Z");
    private static final Instant T2 = Instant.parse("2026-05-08T11:00:00.000000Z");
    private static final Instant T3 = Instant.parse("2026-05-08T12:00:00.000000Z");

    private static AuditLogRow makeEntry(String auditId, String prevHash, Instant ts) {
        String hash = Sha256Util.hashHex(
                (prevHash != null ? prevHash : "")
                + auditId + "USER_REGISTERED" + "actor-1" + "" + "SUCCESS" + ts.toString());
        return new AuditLogRow(auditId, "USER_REGISTERED", "actor-1", "CREATOR",
                null, null, null, null, "SUCCESS", null, null, prevHash, hash, ts);
    }

    @Test
    void singleEntryWithCorrectHash_returnsValid() {
        AuditLogRow entry = makeEntry("aid-1", null, T1);
        when(db.query(anyString(), any())).thenReturn(List.of(entry));

        ChainVerifyResult result = verifier.verify(null);

        assertTrue(result.valid());
        assertEquals(1, result.entriesChecked());
        assertNull(result.firstInvalidAuditId());
    }

    @Test
    void entryWithWrongHash_returnsInvalidAtThatEntry() {
        AuditLogRow tampered = new AuditLogRow("aid-1", "USER_REGISTERED", "actor-1", "CREATOR",
                null, null, null, null, "SUCCESS", null, null, null, "wronghash", T1);
        when(db.query(anyString(), any())).thenReturn(List.of(tampered));

        ChainVerifyResult result = verifier.verify(null);

        assertFalse(result.valid());
        assertEquals(1, result.entriesChecked());
        assertEquals("aid-1", result.firstInvalidAuditId());
    }

    @Test
    void emptyAuditLog_returnsValidWithZeroEntries() {
        when(db.query(anyString(), any())).thenReturn(List.of());

        ChainVerifyResult result = verifier.verify(null);

        assertTrue(result.valid());
        assertEquals(0, result.entriesChecked());
    }

    @Test
    void chainOfThreeEntries_middleTampered_invalidAtEntryTwo() {
        AuditLogRow e1 = makeEntry("aid-1", null, T1);
        // entry 2 has tampered hash
        AuditLogRow e2 = new AuditLogRow("aid-2", "USER_REGISTERED", "actor-1", "CREATOR",
                null, null, null, null, "SUCCESS", null, null, e1.entryHash(), "tampered", T2);
        AuditLogRow e3 = makeEntry("aid-3", e2.entryHash(), T3);
        when(db.query(anyString(), any())).thenReturn(List.of(e1, e2, e3));

        ChainVerifyResult result = verifier.verify(null);

        assertFalse(result.valid());
        assertEquals(2, result.entriesChecked());
        assertEquals("aid-2", result.firstInvalidAuditId());
    }
}
