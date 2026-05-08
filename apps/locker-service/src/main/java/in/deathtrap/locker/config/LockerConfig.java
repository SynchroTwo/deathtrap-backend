package in.deathtrap.locker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Wires JWT validation and transaction infrastructure beans for the locker service. */
@Configuration
public class LockerConfig {

    /** Creates the JwtService bean using JWT_SECRET from environment. */
    @Bean
    public JwtService jwtService() {
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is required");
        }
        return new JwtService(secret);
    }

    /** Exposes TransactionTemplate so DbClient can perform declarative transactions. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager txManager) {
        return new TransactionTemplate(txManager);
    }
}
