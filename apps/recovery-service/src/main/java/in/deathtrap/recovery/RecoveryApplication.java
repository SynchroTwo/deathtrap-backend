package in.deathtrap.recovery;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
/** Spring Boot application for the recovery service. */
@SpringBootApplication(scanBasePackages = {"in.deathtrap.recovery", "in.deathtrap.common"})
public class RecoveryApplication extends SpringBootServletInitializer {
    /** Lambda adapter initialises the Spring context — this main is unused in Lambda. */
    public static void main(String[] args) { new SpringApplicationBuilder(RecoveryApplication.class).run(args); }
}
