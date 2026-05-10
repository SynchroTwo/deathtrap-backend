package in.deathtrap.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

/** Delivers OTPs via SNS in prod; logs them in local and staging (log-mode). */
@Service
public class SnsOtpService {

    private static final Logger log = LoggerFactory.getLogger(SnsOtpService.class);

    private final SnsClient snsClient;

    @Value("${ENVIRONMENT:local}")
    private String environment;

    /** Constructs SnsOtpService with the AWS SNS client. */
    public SnsOtpService(SnsClient snsClient) {
        this.snsClient = snsClient;
    }

    /** Sends an OTP. Skips SNS and logs in local/staging; calls SNS in prod. */
    public void sendOtp(String destination, String channel, String otp, String purpose) {
        if ("local".equals(environment) || "staging".equals(environment)) {
            log.warn("[OTP-LOG-MODE] environment={} channel={} destination={} purpose={} otp={}",
                    environment, channel, maskDestination(destination), purpose, otp);
            return;  // no SNS call
        }
        sendViaSns(destination, channel, otp, purpose);  // prod only
    }

    private String maskDestination(String dest) {
        if (dest == null || dest.length() < 4) { return "***"; }
        return dest.substring(0, dest.length() - 8) + "XXXXXX" + dest.substring(dest.length() - 2);
    }

    private void sendViaSns(String destination, String channel, String otp, String purpose) {
        String message = "Your DeathTrap OTP for " + purpose + " is: " + otp + ". Valid for 10 minutes.";
        snsClient.publish(PublishRequest.builder()
                .phoneNumber(destination)
                .message(message)
                .build());
        log.info("OTP sent via SNS: channel={} purpose={}", channel, purpose);
    }
}
