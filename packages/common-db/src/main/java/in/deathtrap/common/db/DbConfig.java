package in.deathtrap.common.db;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import javax.sql.DataSource;
import org.springframework.data.jdbc.core.dialect.JdbcPostgresDialect;
import org.springframework.data.relational.core.dialect.Dialect;

/** Configures HikariCP connection pool. Reads credentials from Secrets Manager
 *  when DB_SECRET_ARN is set (Lambda/AWS), otherwise falls back to DB_URL /
 *  DB_USERNAME / DB_PASSWORD env vars (local dev). */
@Configuration
public class DbConfig {

    private static final Logger log = LoggerFactory.getLogger(DbConfig.class);

    private static final int MAX_POOL_SIZE = 10;
    private static final int MIN_IDLE = 2;
    private static final long CONNECTION_TIMEOUT_MS = 5000L;
    private static final long IDLE_TIMEOUT_MS = 300_000L;
    private static final long MAX_LIFETIME_MS = 900_000L;

    @Bean
    public Dialect jdbcDialect() {
        return JdbcPostgresDialect.INSTANCE;
    }

    @Bean
    public DataSource dataSource() {
        String dbUrl;
        String dbUsername;
        String dbPassword;
        String environment = System.getenv("ENVIRONMENT");

        String dbSecretArn = System.getenv("DB_SECRET_ARN");
        if (dbSecretArn != null && !dbSecretArn.isBlank()) {
            String region = System.getenv().getOrDefault("AWS_REGION", "ap-south-1");
            try (SecretsManagerClient smClient = SecretsManagerClient.builder()
                    .region(Region.of(region))
                    .build()) {
                String secretJson = smClient.getSecretValue(
                        GetSecretValueRequest.builder().secretId(dbSecretArn).build()
                ).secretString();
                ObjectMapper mapper = new ObjectMapper();
                JsonNode secret = mapper.readTree(secretJson);
                String host = secret.get("host").asText();
                int port = secret.path("port").asInt(5432);
                String dbname = secret.get("dbname").asText();
                dbUrl = String.format("jdbc:postgresql://%s:%d/%s?sslmode=require", host, port, dbname);
                dbUsername = secret.get("username").asText();
                dbPassword = secret.get("password").asText();
                log.info("Loaded DB credentials from Secrets Manager secret {}", dbSecretArn);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to fetch DB credentials from Secrets Manager: " + e.getMessage(), e);
            }
        } else {
            dbUrl = System.getenv("DB_URL");
            dbUsername = System.getenv("DB_USERNAME");
            dbPassword = System.getenv("DB_PASSWORD");

            if (dbUrl == null || dbUrl.isBlank()) {
                throw new IllegalStateException("DB_URL environment variable is required");
            }
            if (dbUsername == null || dbUsername.isBlank()) {
                throw new IllegalStateException("DB_USERNAME environment variable is required");
            }
            if (dbPassword == null || dbPassword.isBlank()) {
                throw new IllegalStateException("DB_PASSWORD environment variable is required");
            }
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
