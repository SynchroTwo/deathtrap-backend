package in.deathtrap.sqsconsumer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.xray.AWSXRay;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.common.types.dto.TriggerMessage;
import in.deathtrap.sqsconsumer.service.ThresholdService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ApplicationContext;

/** Lambda entry point for the SQS trigger consumer. Processes trigger events from SQS. */
public class SqsConsumerHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger log = LoggerFactory.getLogger(SqsConsumerHandler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static volatile ApplicationContext springContext;

    private final ThresholdService thresholdService;

    /** Initialises Spring context on cold start and wires dependencies. */
    public SqsConsumerHandler() {
        this.thresholdService = getContext().getBean(ThresholdService.class);
    }

    private static ApplicationContext getContext() {
        if (springContext == null) {
            synchronized (SqsConsumerHandler.class) {
                if (springContext == null) {
                    springContext = new SpringApplicationBuilder(SqsConsumerApplication.class)
                            .web(WebApplicationType.NONE)
                            .run();
                }
            }
        }
        return springContext;
    }

    /** Processes each SQS message — applies 2-of-3 threshold logic for death signals. */
    @Override
    public Void handleRequest(SQSEvent sqsEvent, Context context) {
        if (sqsEvent == null || sqsEvent.getRecords() == null) {
            return null;
        }
        for (SQSEvent.SQSMessage message : sqsEvent.getRecords()) {
            try {
                processMessage(message);
            } catch (Exception e) {
                log.error("SQS message processing failed: messageId={} error={}",
                        message.getMessageId(), e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
        return null;
    }

    private void processMessage(SQSEvent.SQSMessage message) throws Exception {
        MDC.put("service", "sqs-consumer");
        MDC.put("messageId", message.getMessageId());
        try { AWSXRay.beginSubsegment("threshold-check"); } catch (Exception ignored) { /* X-Ray not active */ }
        try {
            TriggerMessage msg = MAPPER.readValue(message.getBody(), TriggerMessage.class);
            log.info("Processing trigger message: event={} creatorId={} sourceType={}",
                    msg.event(), msg.creatorId(), msg.sourceType());

            if ("BLOB_REBUILD_REQUIRED".equals(msg.event())) {
                log.info("Blob rebuild notification received for creatorId={}", msg.creatorId());
                return;
            }

            thresholdService.processDeathSignal(msg.creatorId(), msg.sourceType(), msg.referenceId());
            try { AWSXRay.getCurrentSubsegment().putAnnotation("creatorId", msg.creatorId()); } catch (Exception ignored) { /* X-Ray not active */ }
        } catch (Exception e) {
            try { AWSXRay.getCurrentSubsegment().addException(e); } catch (Exception ignored) { /* X-Ray not active */ }
            throw e;
        } finally {
            try { AWSXRay.endSubsegment(); } catch (Exception ignored) { /* X-Ray not active */ }
            MDC.clear();
        }
    }
}
