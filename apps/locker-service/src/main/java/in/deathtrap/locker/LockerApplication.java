package in.deathtrap.locker;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the locker service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.locker", "in.deathtrap.common"})
public class LockerApplication extends SpringBootServletInitializer {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        new SpringApplicationBuilder(LockerApplication.class).run(args);
    }
}
