package in.deathtrap.common.db;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.Instant;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Shared base for integration tests — starts one embedded PostgreSQL per JVM,
 * runs all Flyway migrations, and exposes a real DbClient.
 * No Docker required: uses zonky embedded-postgres binaries.
 */
public abstract class IntegrationTestBase {

    protected static final DbClient db;
    protected static final JdbcTemplate jdbc;

    static {
        try {
            EmbeddedPostgres pg = EmbeddedPostgres.start();
            // Wrap DataSource so that java.time.Instant params are converted to
            // java.sql.Timestamp before reaching the PGJDBC driver (which rejects
            // raw Instant in setObject without an explicit SQL type hint).
            DataSource ds = wrapWithInstantSupport(pg.getPostgresDatabase());

            String migrationsPath = Paths.get("../../migrations/sql")
                    .toAbsolutePath().normalize().toString();
            Flyway.configure()
                    .dataSource(ds)
                    .locations("filesystem:" + migrationsPath)
                    .load()
                    .migrate();

            jdbc = new JdbcTemplate(ds);
            TransactionTemplate tt = new TransactionTemplate(new DataSourceTransactionManager(ds));
            db = new DbClient(jdbc, tt);
        } catch (IOException e) {
            throw new RuntimeException("Failed to start embedded PostgreSQL", e);
        }
    }

    @BeforeEach
    void cleanTables() {
        truncate(tablesToClean());
    }

    protected String[] tablesToClean() {
        return new String[0];
    }

    protected void truncate(String... tables) {
        for (String table : tables) {
            jdbc.execute("TRUNCATE TABLE " + table + " CASCADE");
        }
    }

    // --- DataSource proxy to convert java.time.Instant → java.sql.Timestamp ---

    private static DataSource wrapWithInstantSupport(DataSource raw) {
        return new DelegatingDataSource(raw) {
            @Override
            public Connection getConnection() throws java.sql.SQLException {
                return proxyConnection(super.getConnection());
            }
            @Override
            public Connection getConnection(String user, String pass) throws java.sql.SQLException {
                return proxyConnection(super.getConnection(user, pass));
            }
        };
    }

    private static Connection proxyConnection(Connection conn) {
        return (Connection) Proxy.newProxyInstance(
                Connection.class.getClassLoader(),
                new Class<?>[]{Connection.class},
                (proxy, method, args) -> {
                    if ("prepareStatement".equals(method.getName())
                            || "prepareCall".equals(method.getName())) {
                        PreparedStatement ps = (PreparedStatement) method.invoke(conn, args);
                        return proxyPreparedStatement(ps);
                    }
                    return method.invoke(conn, args);
                });
    }

    private static PreparedStatement proxyPreparedStatement(PreparedStatement ps) {
        return (PreparedStatement) Proxy.newProxyInstance(
                PreparedStatement.class.getClassLoader(),
                new Class<?>[]{PreparedStatement.class},
                (InvocationHandler) (proxy, method, args) -> {
                    if ("setObject".equals(method.getName())
                            && args != null && args.length >= 2
                            && args[1] instanceof Instant instant) {
                        ps.setTimestamp((int) args[0], Timestamp.from(instant));
                        return null;
                    }
                    return method.invoke(ps, args);
                });
    }
}
