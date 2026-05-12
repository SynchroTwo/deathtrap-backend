package in.deathtrap.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the audit service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.audit", "in.deathtrap.common"})
public class AuditApplication {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        SpringApplication.run(AuditApplication.class, args);
    }
}
