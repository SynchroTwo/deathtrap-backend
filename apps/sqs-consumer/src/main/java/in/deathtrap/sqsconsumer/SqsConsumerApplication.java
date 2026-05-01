package in.deathtrap.sqsconsumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the SQS trigger consumer. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.sqsconsumer", "in.deathtrap.common"})
public class SqsConsumerApplication {

    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        SpringApplication.run(SqsConsumerApplication.class, args);
    }
}
