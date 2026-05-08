package in.deathtrap.trigger.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Wires trigger-service-specific beans including JWT and transactions. */
@Configuration
public class TriggerConfig {

    @Value("${JWT_SECRET:}")
    private String jwtSecret;

    @Value("${WEBHOOK_SECRET:}")
    private String webhookSecret;

    /** Creates the JwtService bean — requires JWT_SECRET env var. */
    @Bean
    public JwtService jwtService() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is required");
        }
        return new JwtService(jwtSecret);
    }

    /** Validates WEBHOOK_SECRET at startup — throws if not configured. */
    @Bean
    public String webhookSecretBean() {
        if (webhookSecret == null || webhookSecret.isBlank()) {
            throw new IllegalStateException("WEBHOOK_SECRET environment variable is required");
        }
        return webhookSecret;
    }

    /** Creates the TransactionTemplate bean used by DbClient. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager ptm) {
        return new TransactionTemplate(ptm);
    }
}
