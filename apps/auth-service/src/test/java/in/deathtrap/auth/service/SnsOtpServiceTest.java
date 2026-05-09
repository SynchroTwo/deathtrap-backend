package in.deathtrap.auth.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Unit tests for SnsOtpService — no Spring context. */
@ExtendWith(MockitoExtension.class)
class SnsOtpServiceTest {

    @Mock
    private SnsClient snsClient;

    @InjectMocks
    private SnsOtpService snsOtpService;

    @Test
    void sendOtp_stagingEnvironment_doesNotCallSnsClient() {
        ReflectionTestUtils.setField(snsOtpService, "environment", "staging");

        snsOtpService.sendOtp("+919999999990", "sms", "123456", "registration");

        verify(snsClient, never()).publish(any(PublishRequest.class));
    }

    @Test
    void sendOtp_prodEnvironment_callsSnsClient() {
        ReflectionTestUtils.setField(snsOtpService, "environment", "prod");

        snsOtpService.sendOtp("+919999999990", "sms", "123456", "registration");

        verify(snsClient).publish(any(PublishRequest.class));
    }
}
