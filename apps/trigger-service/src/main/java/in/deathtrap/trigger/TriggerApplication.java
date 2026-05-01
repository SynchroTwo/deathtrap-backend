package in.deathtrap.trigger;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/** Spring Boot application for the trigger service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.trigger", "in.deathtrap.common"})
public class TriggerApplication extends SpringBootServletInitializer {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        new SpringApplicationBuilder(TriggerApplication.class).run(args);
    }
}
