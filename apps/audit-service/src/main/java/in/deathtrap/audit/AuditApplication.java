package in.deathtrap.audit;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/** Spring Boot application for the audit service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.audit", "in.deathtrap.common"})
public class AuditApplication extends SpringBootServletInitializer {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuditApplication.class).run(args);
    }
}
