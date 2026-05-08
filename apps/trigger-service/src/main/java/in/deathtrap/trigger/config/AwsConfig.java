package in.deathtrap.trigger.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sqs.SqsClient;

/** Wires AWS SQS and SNS beans used by the trigger service. */
@Configuration
public class AwsConfig {

    @Value("${AWS_REGION:ap-south-1}")
    private String awsRegion;

    /** Creates the SqsClient bean — uses IAM role in Lambda and default credential chain locally. */
    @Bean
    public SqsClient sqsClient() {
        return SqsClient.builder()
                .region(Region.of(awsRegion))
                .build();
    }

    /** Creates the SnsClient bean — used for push and SMS notifications. */
    @Bean
    public SnsClient snsClient() {
        return SnsClient.builder()
                .region(Region.of(awsRegion))
                .build();
    }
}
