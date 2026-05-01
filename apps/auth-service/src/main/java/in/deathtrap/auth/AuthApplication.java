package in.deathtrap.auth;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/** Spring Boot application entry point for the auth service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.auth", "in.deathtrap.common"})
public class AuthApplication extends SpringBootServletInitializer {

    /** Main method — unused in Lambda; Lambda adapter initialises Spring context directly. */
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApplication.class).run(args);
    }
}
