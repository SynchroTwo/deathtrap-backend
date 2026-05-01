package in.deathtrap.sqsconsumer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Lambda entry point for the SQS trigger consumer. Processes trigger events from SQS. */
public class SqsConsumerHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger log = LoggerFactory.getLogger(SqsConsumerHandler.class);

    /** Processes each SQS message — stub implementation for Sprint 1. */
    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        if (event == null || event.getRecords() == null) {
            return null;
        }
        for (SQSEvent.SQSMessage message : event.getRecords()) {
            try {
                log.info("Received SQS message messageId={}", message.getMessageId());
                // SECURITY-STUB: Trigger processing not implemented — Sprint 2
            } catch (Exception ex) {
                log.error("Failed to process SQS message messageId={}", message.getMessageId(), ex);
                throw ex;
            }
        }
        return null;
    }
}
