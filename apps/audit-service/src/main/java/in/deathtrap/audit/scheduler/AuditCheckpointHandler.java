package in.deathtrap.audit.scheduler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import in.deathtrap.audit.AuditApplication;
import in.deathtrap.audit.service.CheckpointService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

/** EventBridge-invoked Lambda that runs the daily audit checkpoint. */
public class AuditCheckpointHandler implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger log = LoggerFactory.getLogger(AuditCheckpointHandler.class);
    private static volatile ApplicationContext context;

    private static ApplicationContext getContext() {
        if (context == null) {
            synchronized (AuditCheckpointHandler.class) {
                if (context == null) {
                    context = new org.springframework.boot.SpringApplication(AuditApplication.class).run();
                }
            }
        }
        return context;
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context lambdaContext) {
        try {
            getContext().getBean(CheckpointService.class).runDailyCheckpoint();
        } catch (Exception e) {
            log.error("Audit checkpoint Lambda failed: error={}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
        return null;
    }
}
