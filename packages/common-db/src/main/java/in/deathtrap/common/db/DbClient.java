package in.deathtrap.common.db;

import in.deathtrap.common.errors.AppException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/** Thin wrapper around JdbcTemplate with uniform error handling. */
@Component
public class DbClient {

    private static final Logger log = LoggerFactory.getLogger(DbClient.class);

    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate transactionTemplate;

    /** Constructs DbClient with the given JdbcTemplate and TransactionTemplate. */
    public DbClient(JdbcTemplate jdbcTemplate, TransactionTemplate transactionTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.transactionTemplate = transactionTemplate;
    }

    /** Executes a query and maps all rows using the given RowMapper. */
    public <T> List<T> query(String sql, RowMapper<T> mapper, Object... params) {
        try {
            return jdbcTemplate.query(sql, mapper, convertParams(params));
        } catch (DataAccessException ex) {
            log.error("Database query failed", ex);
            throw AppException.internalError();
        }
    }

    /** Executes a query and returns at most one row, or empty if none found. */
    public <T> Optional<T> queryOne(String sql, RowMapper<T> mapper, Object... params) {
        try {
            List<T> results = jdbcTemplate.query(sql, mapper, convertParams(params));
            return results.isEmpty() ? Optional.empty() : Optional.of(results.get(0));
        } catch (DataAccessException ex) {
            log.error("Database queryOne failed", ex);
            throw AppException.internalError();
        }
    }

    /** Executes an INSERT, UPDATE, or DELETE and returns the number of affected rows. */
    public int execute(String sql, Object... params) {
        try {
            return jdbcTemplate.update(sql, convertParams(params));
        } catch (DataAccessException ex) {
            log.error("Database execute failed", ex);
            throw AppException.internalError();
        }
    }

    /** PgJDBC does not infer java.time.Instant; convert to Timestamp for binding. */
    private static Object[] convertParams(Object[] params) {
        if (params == null) {
            return null;
        }
        Object[] out = new Object[params.length];
        for (int i = 0; i < params.length; i++) {
            out[i] = (params[i] instanceof Instant) ? Timestamp.from((Instant) params[i]) : params[i];
        }
        return out;
    }

    /** Executes the given callback within a database transaction. */
    public <T> T withTransaction(TransactionCallback<T> callback) {
        try {
            T result = transactionTemplate.execute(callback);
            return result;
        } catch (AppException ex) {
            throw ex;
        } catch (DataAccessException ex) {
            log.error("Transaction failed", ex);
            throw AppException.internalError();
        }
    }
}
