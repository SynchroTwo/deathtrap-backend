package in.deathtrap.common.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/** Configures HikariCP connection pool from environment variables. */
@Configuration
public class DbConfig {

    private static final Logger log = LoggerFactory.getLogger(DbConfig.class);

    private static final int MAX_POOL_SIZE = 10;
    private static final int MIN_IDLE = 2;
    private static final long CONNECTION_TIMEOUT_MS = 5000L;
    private static final long IDLE_TIMEOUT_MS = 300_000L;
    private static final long MAX_LIFETIME_MS = 900_000L;

    /** Creates and configures the HikariCP DataSource bean. */
    @Bean
    public DataSource dataSource() {
        String dbUrl = System.getenv("DB_URL");
        String dbUsername = System.getenv("DB_USERNAME");
        String dbPassword = System.getenv("DB_PASSWORD");
        String environment = System.getenv("ENVIRONMENT");

        if (dbUrl == null || dbUrl.isBlank()) {
            throw new IllegalStateException("DB_URL environment variable is required");
        }
        if (dbUsername == null || dbUsername.isBlank()) {
            throw new IllegalStateException("DB_USERNAME environment variable is required");
        }
        if (dbPassword == null || dbPassword.isBlank()) {
            throw new IllegalStateException("DB_PASSWORD environment variable is required");
        }

        if (!"local".equalsIgnoreCase(environment) && !dbUrl.contains("sslmode=require")) {
            log.warn("DB_URL does not contain sslmode=require — SSL enforcement recommended for non-local environments");
        }

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(dbUrl);
        config.setUsername(dbUsername);
        config.setPassword(dbPassword);
        config.setMaximumPoolSize(MAX_POOL_SIZE);
        config.setMinimumIdle(MIN_IDLE);
        config.setConnectionTimeout(CONNECTION_TIMEOUT_MS);
        config.setIdleTimeout(IDLE_TIMEOUT_MS);
        config.setMaxLifetime(MAX_LIFETIME_MS);
        config.setConnectionTestQuery("SELECT 1");
        config.setPoolName("deathtrap-pool");

        log.info("Initialising HikariCP pool maxSize={} environment={}", MAX_POOL_SIZE, environment);
        return new HikariDataSource(config);
    }
}
