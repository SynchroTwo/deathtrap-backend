package in.deathtrap.common.response;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Adds baseline security response headers to every HTTP response, shared by every HTTP
 * service (auth/locker/recovery/trigger/audit pick it up via their
 * {@code scanBasePackages = "in.deathtrap.common"}).
 *
 * <p>These services serve through Spring MVC controllers ({@code @PostMapping}, etc.) via
 * {@code SpringBootLambdaContainerHandler}, which bypasses {@link ResponseBuilder} (that
 * only decorates the raw {@code APIGatewayProxyResponseEvent} path). So the headers
 * declared there never reached MVC responses — this filter closes that gap by setting them
 * on the servlet response, which aws-serverless-java-container maps back to API Gateway.
 *
 * <p>Ordered just after the CORS filter so an {@code OPTIONS} preflight (short-circuited by
 * {@code CorsFilter} at highest precedence) is unaffected; all real responses get the
 * headers.
 */
@Configuration
public class SecurityHeadersConfig {

    /** Registers the security-headers filter, just after CORS. */
    @Bean
    public FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilterRegistration() {
        FilterRegistrationBean<SecurityHeadersFilter> registration =
                new FilterRegistrationBean<>(new SecurityHeadersFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }

    /** Sets HSTS, anti-clickjacking, MIME-sniffing and no-store cache headers. */
    static final class SecurityHeadersFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(
                HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            response.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            chain.doFilter(request, response);
        }
    }
}
