package in.deathtrap.trigger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the trigger service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.trigger", "in.deathtrap.common"})
public class TriggerApplication {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        SpringApplication.run(TriggerApplication.class, args);
    }
}
