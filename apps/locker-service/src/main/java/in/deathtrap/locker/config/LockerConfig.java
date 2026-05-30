package in.deathtrap.locker.config;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.notification.ActionLinkTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.ses.SesClient;

/** Wires JWT validation, SES, and transaction infrastructure beans. */
@Configuration
public class LockerConfig {

    private static final Logger log = LoggerFactory.getLogger(LockerConfig.class);

    /** Resolves the HS256 signing secret once for both JwtService and
     *  ActionLinkTokenService. Reads JWT_SECRET_ARN from Secrets Manager when
     *  set, otherwise falls back to JWT_SECRET env var (local dev). */
    @Bean
    public String jwtSigningSecret() {
        String jwtSecretArn = System.getenv("JWT_SECRET_ARN");
        if (jwtSecretArn != null && !jwtSecretArn.isBlank()) {
            String region = System.getenv().getOrDefault("AWS_REGION", "ap-south-1");
            try (SecretsManagerClient smClient = SecretsManagerClient.builder()
                    .region(Region.of(region))
                    .build()) {
                String secret = smClient.getSecretValue(
                        GetSecretValueRequest.builder().secretId(jwtSecretArn).build()
                ).secretString();
                log.info("Loaded JWT secret from Secrets Manager secret {}", jwtSecretArn);
                return secret;
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to fetch JWT secret from Secrets Manager: " + e.getMessage(), e);
            }
        }
        String envSecret = System.getenv("JWT_SECRET");
        if (envSecret == null || envSecret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET_ARN or JWT_SECRET environment variable is required");
        }
        return envSecret;
    }

    /** Session-token validator. */
    @Bean
    public JwtService jwtService(String jwtSigningSecret, DbClient dbClient) {
        return new JwtService(jwtSigningSecret, dbClient);
    }

    /** Closure-object email-link token mint/verify (E011 Phase 1B §11.3 + Phase 1C §8). */
    @Bean
    public ActionLinkTokenService actionLinkTokenService(String jwtSigningSecret) {
        return new ActionLinkTokenService(jwtSigningSecret);
    }

    /** AWS SES client used by the notification-sender fan-out methods. */
    @Bean
    public SesClient sesClient() {
        String region = System.getenv().getOrDefault("AWS_REGION", "ap-south-1");
        return SesClient.builder().region(Region.of(region)).build();
    }

    /** Exposes TransactionTemplate so DbClient can perform declarative transactions. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager txManager) {
        return new TransactionTemplate(txManager);
    }
}
