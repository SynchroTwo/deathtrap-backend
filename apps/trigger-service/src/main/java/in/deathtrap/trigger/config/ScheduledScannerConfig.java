package in.deathtrap.trigger.config;

import org.springframework.context.annotation.Configuration;

/**
 * Marker configuration for the EventBridge-scheduled inactivity scanner.
 * Infrastructure: EventBridge rule cron(0 6 * * ? *) → Lambda InactivityScannerHandler::handleRequest.
 */
@Configuration
public class ScheduledScannerConfig {
    // EventBridge scheduling is configured in AWS infrastructure.
    // InactivityScannerHandler initialises its own Spring context on cold start.
}
