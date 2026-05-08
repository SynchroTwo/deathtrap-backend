package in.deathtrap.audit.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Wires audit-service-specific beans including JWT validation and transactions. */
@Configuration
public class AuditConfig {

    @Value("${JWT_SECRET:}")
    private String jwtSecret;

    /** Creates the JwtService bean — requires JWT_SECRET env var. */
    @Bean
    public JwtService jwtService() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is required");
        }
        return new JwtService(jwtSecret);
    }

    /** Creates the TransactionTemplate bean used by DbClient. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager ptm) {
        return new TransactionTemplate(ptm);
    }
}
