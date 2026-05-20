package in.deathtrap.auth.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * Global CORS for browser clients.
 *
 * <p>The API Gateway proxies {@code ANY} (including the {@code OPTIONS} preflight) to this
 * Lambda, so CORS is handled here in Spring rather than at the gateway — no CDK change. The
 * {@link CorsFilter} runs at highest precedence so a preflight short-circuits with the
 * required headers before any handler/auth logic.
 *
 * <p>Allowed origins come from {@code CORS_ALLOWED_ORIGINS} (comma-separated; supports
 * patterns like {@code http://localhost:*} or {@code https://app.example.com}). When unset
 * (non-prod), any localhost/127.0.0.1 port is allowed so UI dev servers (8080, 5173, 3000, …)
 * work out of the box. Set the env var in prod to the real UI origin(s).
 */
@Configuration
public class CorsConfig {

    /** Registers the global CORS filter ahead of all other filters. */
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(allowedOriginPatterns());
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        cfg.setExposedHeaders(List.of("X-Request-Id"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);

        FilterRegistrationBean<CorsFilter> registration =
                new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    private static List<String> allowedOriginPatterns() {
        String env = System.getenv("CORS_ALLOWED_ORIGINS");
        if (env != null && !env.isBlank()) {
            return Arrays.stream(env.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList();
        }
        return List.of("http://localhost:*", "https://localhost:*", "http://127.0.0.1:*");
    }
}
