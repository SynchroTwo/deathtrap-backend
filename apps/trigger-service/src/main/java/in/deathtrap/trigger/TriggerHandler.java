package in.deathtrap.trigger;

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import com.amazonaws.serverless.proxy.model.AwsProxyRequest;
import com.amazonaws.serverless.proxy.model.AwsProxyResponse;
import com.amazonaws.serverless.proxy.spring.SpringBootLambdaContainerHandler;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Lambda entry point for the trigger service. */
public class TriggerHandler implements RequestHandler<AwsProxyRequest, AwsProxyResponse> {
    private static final Logger log = LoggerFactory.getLogger(TriggerHandler.class);
    private static final SpringBootLambdaContainerHandler<AwsProxyRequest, AwsProxyResponse> HANDLER;
    static {
        try {
            HANDLER = SpringBootLambdaContainerHandler.getAwsProxyHandler(TriggerApplication.class);
        } catch (ContainerInitializationException ex) {
            log.error("Cold start failed", ex);
            throw new RuntimeException("Cold start failed", ex);
        }
    }
    /** Delegates to Spring MVC dispatcher. */
    @Override
    public AwsProxyResponse handleRequest(AwsProxyRequest input, Context context) {
        return HANDLER.proxy(input, context);
    }
}
