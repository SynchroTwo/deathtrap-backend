package in.deathtrap.common.audit;

import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import java.util.Map;

/** Payload describing a single audit log entry to be written. */
public record AuditWritePayload(
        AuditEventType eventType,
        String actorId,
        PartyType actorType,
        String targetId,
        String targetType,
        String sessionId,
        String ipAddress,
        String deviceId,
        AuditResult result,
        String failureReason,
        Map<String, Object> metadataJson
) {
    /** Builder for constructing AuditWritePayload instances. */
    public static Builder builder(AuditEventType eventType, AuditResult result) {
        return new Builder(eventType, result);
    }

    /** Fluent builder for AuditWritePayload. */
    public static final class Builder {
        private final AuditEventType eventType;
        private final AuditResult result;
        private String actorId;
        private PartyType actorType;
        private String targetId;
        private String targetType;
        private String sessionId;
        private String ipAddress;
        private String deviceId;
        private String failureReason;
        private Map<String, Object> metadataJson;

        private Builder(AuditEventType eventType, AuditResult result) {
            this.eventType = eventType;
            this.result = result;
        }

        /** Sets the actor (party performing the action). */
        public Builder actorId(String actorId) { this.actorId = actorId; return this; }

        /** Sets the type of the acting party. */
        public Builder actorType(PartyType actorType) { this.actorType = actorType; return this; }

        /** Sets the target of the action. */
        public Builder targetId(String targetId) { this.targetId = targetId; return this; }

        /** Sets a human-readable label for the target type. */
        public Builder targetType(String targetType) { this.targetType = targetType; return this; }

        /** Sets the session identifier for this action. */
        public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }

        /** Sets the IP address of the request. */
        public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }

        /** Sets the device identifier. */
        public Builder deviceId(String deviceId) { this.deviceId = deviceId; return this; }

        /** Sets the human-readable failure reason for failed events. */
        public Builder failureReason(String failureReason) { this.failureReason = failureReason; return this; }

        /** Sets additional structured metadata. Must not contain PII or key material. */
        public Builder metadataJson(Map<String, Object> metadataJson) { this.metadataJson = metadataJson; return this; }

        /** Builds the AuditWritePayload. */
        public AuditWritePayload build() {
            return new AuditWritePayload(eventType, actorId, actorType, targetId,
                    targetType, sessionId, ipAddress, deviceId, result, failureReason, metadataJson);
        }
    }
}
