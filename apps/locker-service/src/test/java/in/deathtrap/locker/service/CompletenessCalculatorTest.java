package in.deathtrap.locker.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.locker.service.CompletenessCalculator.CompletenessScore;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for CompletenessCalculator — no Spring context. */
@ExtendWith(MockitoExtension.class)
class CompletenessCalculatorTest {

    @Mock private DbClient db;

    @InjectMocks private CompletenessCalculator calculator;

    // countByStatus → 2-vararg (lockerId, status)
    // countByStatusAndType → 3-vararg (lockerId, status, assetType)
    // Separate stubs are needed because Mockito matches varargs by element count.

    @Test
    void noFilledNoSkipped_returnsZero() {
        when(db.query(anyString(), any(), any(), any()))             // 2-vararg: countByStatus
                .thenReturn(List.of(0L))
                .thenReturn(List.of(0L));
        when(db.query(anyString(), any(), any(), any(), any()))      // 3-vararg: countByStatusAndType
                .thenReturn(List.of(0L))
                .thenReturn(List.of(0L))
                .thenReturn(List.of(0L))
                .thenReturn(List.of(0L));

        CompletenessScore score = calculator.recalculate("locker-1");

        assertEquals(0, score.overall());
        assertEquals(0, score.onlinePct());
        assertEquals(0, score.offlinePct());
    }

    @Test
    void fifteenFilledZeroSkipped_returns50PercentOverall() {
        when(db.query(anyString(), any(), any(), any()))
                .thenReturn(List.of(15L)) // filled
                .thenReturn(List.of(0L)); // skipped
        when(db.query(anyString(), any(), any(), any(), any()))
                .thenReturn(List.of(7L))  // online filled
                .thenReturn(List.of(0L))  // online skipped
                .thenReturn(List.of(8L))  // offline filled
                .thenReturn(List.of(0L)); // offline skipped

        CompletenessScore score = calculator.recalculate("locker-1");

        assertEquals(50, score.overall());   // 15/30
        assertEquals(50, score.onlinePct()); // 7/14
        assertEquals(50, score.offlinePct()); // 8/16
    }

    @Test
    void allThirtyFilled_returns100Percent() {
        when(db.query(anyString(), any(), any(), any()))
                .thenReturn(List.of(30L)) // filled
                .thenReturn(List.of(0L)); // skipped
        when(db.query(anyString(), any(), any(), any(), any()))
                .thenReturn(List.of(14L)) // online filled
                .thenReturn(List.of(0L))  // online skipped
                .thenReturn(List.of(16L)) // offline filled
                .thenReturn(List.of(0L)); // offline skipped

        CompletenessScore score = calculator.recalculate("locker-1");

        assertEquals(100, score.overall());
        assertEquals(100, score.onlinePct());
        assertEquals(100, score.offlinePct());
    }

    @Test
    void mixedOnlineOffline_splitsCorrectly() {
        when(db.query(anyString(), any(), any(), any()))
                .thenReturn(List.of(7L))  // filled
                .thenReturn(List.of(0L)); // skipped
        when(db.query(anyString(), any(), any(), any(), any()))
                .thenReturn(List.of(7L))  // online filled (all 7 online)
                .thenReturn(List.of(0L))  // online skipped
                .thenReturn(List.of(0L))  // offline filled
                .thenReturn(List.of(0L)); // offline skipped

        CompletenessScore score = calculator.recalculate("locker-1");

        assertEquals(23, score.overall());   // 7/30 * 100 (int trunc)
        assertEquals(50, score.onlinePct()); // 7/14 * 100
        assertEquals(0, score.offlinePct());
    }
}
