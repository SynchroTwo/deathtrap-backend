package in.deathtrap.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.sns.SnsClient;

/** Wires JWT, AWS SDK, and transaction infrastructure beans. */
@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /** Creates the JwtService bean using JWT_SECRET from environment. */
    @Bean
    public JwtService jwtService() {
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is required");
        }
        if (secret.length() < 32) {
            log.warn("JWT_SECRET is shorter than recommended 32 characters");
        }
        return new JwtService(secret);
    }

    /** Creates the AWS SNS client bean. */
    @Bean
    public SnsClient snsClient() {
        String region = System.getenv("AWS_REGION");
        if (region == null || region.isBlank()) { region = "ap-south-1"; }
        return SnsClient.builder().region(Region.of(region)).build();
    }

    /** Creates the AWS SES client bean. */
    @Bean
    public SesClient sesClient() {
        String region = System.getenv("AWS_REGION");
        if (region == null || region.isBlank()) { region = "ap-south-1"; }
        return SesClient.builder().region(Region.of(region)).build();
    }

    /** Exposes TransactionTemplate so DbClient can perform declarative transactions. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager txManager) {
        return new TransactionTemplate(txManager);
    }
}
