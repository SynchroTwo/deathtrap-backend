package in.deathtrap.locker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot application for the locker service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.locker", "in.deathtrap.common"})
public class LockerApplication {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) {
        SpringApplication.run(LockerApplication.class, args);
    }
}
