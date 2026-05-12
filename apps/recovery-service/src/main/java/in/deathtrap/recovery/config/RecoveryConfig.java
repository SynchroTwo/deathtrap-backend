package in.deathtrap.recovery.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/** Wires recovery-service-specific beans. */
@Configuration
public class RecoveryConfig {

    private static final Logger log = LoggerFactory.getLogger(RecoveryConfig.class);

    /** Creates the JwtService bean. Reads JWT_SECRET_ARN from Secrets Manager when
     *  set (Lambda/AWS), otherwise falls back to JWT_SECRET env var (local dev). */
    @Bean
    public JwtService jwtService() {
        String secret;
        String jwtSecretArn = System.getenv("JWT_SECRET_ARN");
        if (jwtSecretArn != null && !jwtSecretArn.isBlank()) {
            String region = System.getenv().getOrDefault("AWS_REGION", "ap-south-1");
            try (SecretsManagerClient smClient = SecretsManagerClient.builder()
                    .region(Region.of(region))
                    .build()) {
                secret = smClient.getSecretValue(
                        GetSecretValueRequest.builder().secretId(jwtSecretArn).build()
                ).secretString();
                log.info("Loaded JWT secret from Secrets Manager secret {}", jwtSecretArn);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to fetch JWT secret from Secrets Manager: " + e.getMessage(), e);
            }
        } else {
            secret = System.getenv("JWT_SECRET");
            if (secret == null || secret.isBlank()) {
                throw new IllegalStateException("JWT_SECRET_ARN or JWT_SECRET environment variable is required");
            }
        }
        return new JwtService(secret);
    }

    /** Creates the TransactionTemplate bean used by DbClient. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager ptm) {
        return new TransactionTemplate(ptm);
    }
}
