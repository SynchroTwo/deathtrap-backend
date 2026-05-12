package in.deathtrap.recovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the recovery service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.recovery", "in.deathtrap.common"})
public class RecoveryApplication {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) { SpringApplication.run(RecoveryApplication.class, args); }
}
