package in.deathtrap.auth;

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import com.amazonaws.serverless.proxy.model.AwsProxyRequest;
import com.amazonaws.serverless.proxy.model.AwsProxyResponse;
import com.amazonaws.serverless.proxy.spring.SpringBootLambdaContainerHandler;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Lambda entry point — lazily initialises the Spring context on first invocation. */
public class AuthHandler implements RequestHandler<AwsProxyRequest, AwsProxyResponse> {

    private static final Logger log = LoggerFactory.getLogger(AuthHandler.class);
    private static final SpringBootLambdaContainerHandler<AwsProxyRequest, AwsProxyResponse> HANDLER;

    static {
        try {
            HANDLER = SpringBootLambdaContainerHandler.getAwsProxyHandler(AuthApplication.class);
            Runtime.getRuntime().addShutdownHook(new Thread(() ->
                    log.info("Auth Lambda shutting down")));
        } catch (ContainerInitializationException ex) {
            log.error("Failed to initialise Spring container during cold start", ex);
            throw new RuntimeException("Cold start failed — Spring context could not be initialised", ex);
        }
    }

    /** Handles an API Gateway proxy request by delegating to the Spring MVC dispatcher. */
    @Override
    public AwsProxyResponse handleRequest(AwsProxyRequest input, Context context) {
        return HANDLER.proxy(input, context);
    }
}
