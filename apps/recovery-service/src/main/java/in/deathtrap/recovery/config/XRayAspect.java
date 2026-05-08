package in.deathtrap.recovery.config;

import com.amazonaws.xray.AWSXRay;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

/** Adds an X-Ray subsegment around every route handler method for distributed tracing. */
@Aspect
@Component
public class XRayAspect {

    @Around("within(in.deathtrap.recovery.routes..*)")
    public Object traceHandler(ProceedingJoinPoint pjp) throws Throwable {
        String name = pjp.getSignature().getDeclaringType().getSimpleName();
        try { AWSXRay.beginSubsegment(name); } catch (Exception ignored) { /* X-Ray not active */ }
        try {
            Object result = pjp.proceed();
            try { AWSXRay.getCurrentSubsegment().putAnnotation("outcome", "success"); } catch (Exception ignored) { /* X-Ray not active */ }
            return result;
        } catch (Throwable t) {
            try { AWSXRay.getCurrentSubsegment().putAnnotation("outcome", "error"); } catch (Exception ignored) { /* X-Ray not active */ }
            throw t;
        } finally {
            try { AWSXRay.endSubsegment(); } catch (Exception ignored) { /* X-Ray not active */ }
        }
    }
}
