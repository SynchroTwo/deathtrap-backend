package in.deathtrap.trigger.scheduler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import in.deathtrap.trigger.TriggerApplication;
import in.deathtrap.trigger.service.InactivityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ApplicationContext;

/** Lambda handler invoked daily by EventBridge cron to scan for overdue inactivity checks. */
public class InactivityScannerHandler implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger log = LoggerFactory.getLogger(InactivityScannerHandler.class);

    private static volatile ApplicationContext springContext;

    private static ApplicationContext getContext() {
        if (springContext == null) {
            synchronized (InactivityScannerHandler.class) {
                if (springContext == null) {
                    springContext = new SpringApplicationBuilder(TriggerApplication.class)
                            .web(WebApplicationType.NONE)
                            .run();
                }
            }
        }
        return springContext;
    }

    /** Runs the inactivity scan on each EventBridge invocation. */
    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {
        log.info("InactivityScannerHandler invoked: source={}", event != null ? event.getSource() : "unknown");
        try {
            getContext().getBean(InactivityService.class).scanAndEscalate();
        } catch (Exception e) {
            log.error("Inactivity scan failed: {}", e.getMessage(), e);
            throw e;
        }
        return null;
    }
}
