package in.deathtrap.locker;

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import com.amazonaws.serverless.proxy.model.AwsProxyRequest;
import com.amazonaws.serverless.proxy.model.AwsProxyResponse;
import com.amazonaws.serverless.proxy.spring.SpringBootLambdaContainerHandler;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/** Lambda entry point for the locker service. */
public class LockerHandler implements RequestHandler<AwsProxyRequest, AwsProxyResponse> {
    private static final Logger log = LoggerFactory.getLogger(LockerHandler.class);
    private static final SpringBootLambdaContainerHandler<AwsProxyRequest, AwsProxyResponse> HANDLER;
    static {
        try {
            HANDLER = SpringBootLambdaContainerHandler.getAwsProxyHandler(LockerApplication.class);
        } catch (ContainerInitializationException ex) {
            log.error("Cold start failed", ex);
            throw new RuntimeException("Cold start failed", ex);
        }
    }
    /** Delegates to Spring MVC dispatcher. */
    @Override
    public AwsProxyResponse handleRequest(AwsProxyRequest input, Context context) {
        MDC.put("service", "locker-service");
        if (input.getRequestContext() != null) {
            MDC.put("requestId", input.getRequestContext().getRequestId());
        }
        try {
            return HANDLER.proxy(input, context);
        } finally {
            MDC.clear();
        }
    }
}
