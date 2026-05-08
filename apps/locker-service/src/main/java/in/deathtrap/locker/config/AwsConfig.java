package in.deathtrap.locker.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;

/** Wires AWS S3 beans used by the locker service. */
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

    /** Creates the S3Presigner bean for generating short-lived presigned GET URLs. */
    @Bean
    public S3Presigner s3Presigner() {
        return S3Presigner.builder()
                .region(Region.of(awsRegion))
                .build();
    }
}
