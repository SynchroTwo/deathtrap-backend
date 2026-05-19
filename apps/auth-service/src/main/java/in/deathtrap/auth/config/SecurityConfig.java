package in.deathtrap.auth.config;

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
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sqs.SqsClient;

/** Wires JWT, AWS SDK, and transaction infrastructure beans. */
@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

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
        if (secret.length() < 32) {
            log.warn("JWT secret is shorter than recommended 32 characters");
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

    /** Creates the AWS SQS client bean. */
    @Bean
    public SqsClient sqsClient() {
        String region = System.getenv("AWS_REGION");
        if (region == null || region.isBlank()) { region = "ap-south-1"; }
        return SqsClient.builder().region(Region.of(region)).build();
    }

    /** Exposes TransactionTemplate so DbClient can perform declarative transactions. */
    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager txManager) {
        return new TransactionTemplate(txManager);
    }
}
