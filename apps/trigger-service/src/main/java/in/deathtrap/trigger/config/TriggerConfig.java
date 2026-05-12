package in.deathtrap.trigger.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/** Wires trigger-service-specific beans including JWT and transactions. */
@Configuration
public class TriggerConfig {

    private static final Logger log = LoggerFactory.getLogger(TriggerConfig.class);

    /** Creates the JwtService bean. Reads JWT_SECRET_ARN from Secrets Manager when
     *  set (Lambda/AWS), otherwise falls back to JWT_SECRET env var (local dev). */
    @Bean
    public JwtService jwtService() {
        return new JwtService(loadSecret("JWT_SECRET_ARN", "JWT_SECRET"));
    }

    /** Loads WEBHOOK_SECRET from Secrets Manager (via WEBHOOK_SECRET_ARN) or env var. */
    @Bean
    public String webhookSecretBean() {
        return loadSecret("WEBHOOK_SECRET_ARN", "WEBHOOK_SECRET");
    }

    /** Creates the TransactionTemplate bean used by DbClient. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager ptm) {
        return new TransactionTemplate(ptm);
    }

    private static String loadSecret(String arnVar, String fallbackVar) {
        String arn = System.getenv(arnVar);
        if (arn != null && !arn.isBlank()) {
            String region = System.getenv().getOrDefault("AWS_REGION", "ap-south-1");
            try (SecretsManagerClient smClient = SecretsManagerClient.builder()
                    .region(Region.of(region))
                    .build()) {
                String value = smClient.getSecretValue(
                        GetSecretValueRequest.builder().secretId(arn).build()
                ).secretString();
                log.info("Loaded {} from Secrets Manager secret {}", fallbackVar, arn);
                return value;
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to fetch " + fallbackVar + " from Secrets Manager: " + e.getMessage(), e);
            }
        }
        String value = System.getenv(fallbackVar);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(arnVar + " or " + fallbackVar + " environment variable is required");
        }
        return value;
    }
}
