package in.deathtrap.locker.service;

import in.deathtrap.common.db.DbClient;
import java.util.List;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/** Recalculates locker completeness percentages from the live asset_index counts. */
@Component
public class CompletenessCalculator {

    private static final int TOTAL_ASSETS = 24;
    private static final int ONLINE_ASSETS = 12;
    private static final int OFFLINE_ASSETS = 12;

    private static final String COUNT_BY_STATUS =
            "SELECT COUNT(*) FROM asset_index WHERE locker_id = ? AND status = ?::asset_status_enum";
    private static final String COUNT_BY_STATUS_AND_TYPE =
            "SELECT COUNT(*) FROM asset_index WHERE locker_id = ? AND status = ?::asset_status_enum " +
            "AND asset_type = ?::asset_type_enum";

    private static final RowMapper<Long> COUNT_MAPPER = (rs, row) -> rs.getLong(1);

    private final DbClient db;

    /** Constructs CompletenessCalculator with the given DbClient. */
    public CompletenessCalculator(DbClient db) {
        this.db = db;
    }

    /** Recalculates overall, online, and offline completeness percentages for the given locker. */
    public CompletenessScore recalculate(String lockerId) {
        int filled  = countByStatus(lockerId, "filled");
        int skipped = countByStatus(lockerId, "skipped");
        int overall = ((filled + skipped) * 100) / TOTAL_ASSETS;

        int onlineFilled  = countByStatusAndType(lockerId, "filled",  "online");
        int onlineSkipped = countByStatusAndType(lockerId, "skipped", "online");
        int onlinePct     = ((onlineFilled + onlineSkipped) * 100) / ONLINE_ASSETS;

        int offlineFilled  = countByStatusAndType(lockerId, "filled",  "offline");
        int offlineSkipped = countByStatusAndType(lockerId, "skipped", "offline");
        int offlinePct     = ((offlineFilled + offlineSkipped) * 100) / OFFLINE_ASSETS;

        return new CompletenessScore(overall, onlinePct, offlinePct);
    }

    private int countByStatus(String lockerId, String status) {
        List<Long> rows = db.query(COUNT_BY_STATUS, COUNT_MAPPER, lockerId, status);
        return rows.isEmpty() ? 0 : rows.get(0).intValue();
    }

    private int countByStatusAndType(String lockerId, String status, String assetType) {
        List<Long> rows = db.query(COUNT_BY_STATUS_AND_TYPE, COUNT_MAPPER, lockerId, status, assetType);
        return rows.isEmpty() ? 0 : rows.get(0).intValue();
    }

    /** Computed completeness scores for a locker. */
    public record CompletenessScore(int overall, int onlinePct, int offlinePct) {}
}
