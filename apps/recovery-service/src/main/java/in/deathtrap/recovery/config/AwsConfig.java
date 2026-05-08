package in.deathtrap.recovery.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

/** Wires AWS S3 beans used by the recovery service. */
@Configuration
public class AwsConfig {

    @Value("${AWS_REGION:ap-south-1}")
    private String awsRegion;

    /** Creates the S3Client bean — uses IAM role in Lambda and default credential chain locally. */
    @Bean
    public S3Client s3Client() {
        return S3Client.builder()
                .region(Region.of(awsRegion))
                .build();
    }
}
