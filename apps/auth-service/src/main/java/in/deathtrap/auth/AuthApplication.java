package in.deathtrap.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application entry point for the auth service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.auth", "in.deathtrap.common"})
public class AuthApplication {

    /** Main method — unused in Lambda; Lambda adapter initialises Spring context directly. */
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
