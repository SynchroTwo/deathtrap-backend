package in.deathtrap.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.errors.AppException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Verifies client-signed nominee invite tokens (Path A).
 *
 * <p>The creator's browser produces the token as
 * {@code base64url( utf8( canonicalJson({payload, signature}) ) )} where
 * {@code signature = base64( ECDSA_P256_P1363( SHA-256( canonicalJson(payload) ) ) )}.
 * Because WebCrypto's {@code ECDSA{hash:"SHA-256"}} hashes its input again, the actual
 * signed digest is {@code SHA-256(SHA-256(canonicalJson(payload)))}.
 *
 * <p>Verification deliberately does <b>not</b> re-canonicalize the payload. The outer
 * object sorts {@code payload} before {@code signature}, so the payload object embedded
 * in the decoded token is byte-identical to {@code canonicalJson(payload)} — i.e. the
 * exact bytes that were signed. We extract that substring verbatim (brace-balanced,
 * string-aware) and verify over it, eliminating any cross-platform canonical-JSON
 * byte-mismatch risk. Field reads use a normal JSON parse of those same bytes.
 */
public final class InviteTokenVerifier {

    public static final String EXPECTED_PURPOSE = "creator-invite-nominee";
    public static final int EXPECTED_SCHEMA_VERSION = 1;
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSAinP1363Format";
    private static final Pattern PEM_HEADERS = Pattern.compile(
            "-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private InviteTokenVerifier() {}

    /** The validated invite-token payload plus the raw signed bytes (for diagnostics/tests). */
    public record ParsedInvite(
            int schemaVersion,
            String purpose,
            String creatorId,
            String creatorName,
            String nomineeId,
            String fullName,
            String email,
            String mobile,
            Instant expiresAt,
            String nonce,
            byte[] payloadBytes,
            byte[] signature) {}

    /**
     * Parses and cryptographically verifies an invite token against a creator's PEM pubkey.
     * Performs intrinsic validity checks (schema version, purpose, expiry, signature).
     * Caller is responsible for DB-linkage checks (nominee belongs to creator, status=invited).
     *
     * @throws AppException AUTH_INVITE_INVALID for malformed token / wrong purpose / bad signature,
     *                      AUTH_INVITE_EXPIRED when expiresAt is in the past.
     */
    public static ParsedInvite verify(String token, String creatorPubkeyPem) {
        if (token == null || token.isBlank() || creatorPubkeyPem == null || creatorPubkeyPem.isBlank()) {
            throw AppException.inviteInvalid();
        }

        String json;
        try {
            json = new String(Base64.getUrlDecoder().decode(token.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw AppException.inviteInvalid();
        }

        byte[] payloadBytes = extractObjectBytes(json, "payload");
        byte[] signature = decodeSignature(json);

        JsonNode payload = parsePayload(payloadBytes);
        int schemaVersion = payload.path("schemaVersion").asInt(-1);
        String purpose = textOrNull(payload, "purpose");
        if (schemaVersion != EXPECTED_SCHEMA_VERSION || !EXPECTED_PURPOSE.equals(purpose)) {
            throw AppException.inviteInvalid();
        }

        Instant expiresAt = parseInstant(textOrNull(payload, "expiresAt"));
        if (expiresAt.isBefore(Instant.now())) {
            throw AppException.inviteExpired();
        }

        verifySignature(payloadBytes, signature, creatorPubkeyPem);

        return new ParsedInvite(
                schemaVersion,
                purpose,
                textOrNull(payload, "creatorId"),
                textOrNull(payload, "creatorName"),
                textOrNull(payload, "nomineeId"),
                textOrNull(payload, "fullName"),
                textOrNull(payload, "email"),
                textOrNull(payload, "mobile"),
                expiresAt,
                textOrNull(payload, "nonce"),
                payloadBytes,
                signature);
    }

    /**
     * Extracts {@code creatorId} from the token's payload <b>without</b> verifying the signature.
     * Used only to resolve which creator's pubkey to verify against; the subsequent
     * {@link #verify} call cryptographically binds the token to that creator's key.
     */
    public static String peekCreatorId(String token) {
        if (token == null || token.isBlank()) {
            throw AppException.inviteInvalid();
        }
        String json;
        try {
            json = new String(Base64.getUrlDecoder().decode(token.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw AppException.inviteInvalid();
        }
        String creatorId = textOrNull(parsePayload(extractObjectBytes(json, "payload")), "creatorId");
        if (creatorId == null || creatorId.isBlank()) {
            throw AppException.inviteInvalid();
        }
        return creatorId;
    }

    private static void verifySignature(byte[] payloadBytes, byte[] signature, String pem) {
        byte[] inner = Sha256Util.hash(payloadBytes);
        try {
            PublicKey pubkey = loadEcPublicKey(pem);
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(pubkey);
            verifier.update(inner);
            if (!verifier.verify(signature)) {
                throw AppException.inviteInvalid();
            }
        } catch (AppException ex) {
            throw ex;
        } catch (Exception ex) {
            throw AppException.inviteInvalid();
        }
    }

    private static PublicKey loadEcPublicKey(String pem) {
        try {
            String b64 = PEM_HEADERS.matcher(pem).replaceAll("");
            byte[] der = Base64.getDecoder().decode(b64);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception ex) {
            throw AppException.inviteInvalid();
        }
    }

    private static JsonNode parsePayload(byte[] payloadBytes) {
        try {
            return MAPPER.readTree(payloadBytes);
        } catch (Exception ex) {
            throw AppException.inviteInvalid();
        }
    }

    private static byte[] decodeSignature(String json) {
        String value = extractStringValue(json, "signature");
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            throw AppException.inviteInvalid();
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode child = node.get(field);
        if (child == null || child.isNull()) {
            return null;
        }
        return child.asText();
    }

    private static Instant parseInstant(String value) {
        if (value == null) {
            throw AppException.inviteInvalid();
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw AppException.inviteInvalid();
        }
    }

    /**
     * Returns the UTF-8 bytes of the JSON object value of {@code key}, verbatim, from the
     * outer token JSON. Brace-counting respects JSON string literals and escapes so that a
     * brace inside a string value (e.g. a name containing '{') does not corrupt the scan.
     */
    private static byte[] extractObjectBytes(String json, String key) {
        int keyIdx = json.indexOf('"' + key + '"');
        if (keyIdx < 0) {
            throw AppException.inviteInvalid();
        }
        int start = json.indexOf('{', keyIdx + key.length() + 2);
        if (start < 0) {
            throw AppException.inviteInvalid();
        }
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return json.substring(start, i + 1).getBytes(StandardCharsets.UTF_8);
                }
            }
        }
        throw AppException.inviteInvalid();
    }

    /** Returns the unescaped string value of a top-level string field (e.g. "signature"). */
    private static String extractStringValue(String json, String key) {
        int keyIdx = json.indexOf('"' + key + '"');
        if (keyIdx < 0) {
            throw AppException.inviteInvalid();
        }
        int quote = json.indexOf('"', keyIdx + key.length() + 2);
        if (quote < 0) {
            throw AppException.inviteInvalid();
        }
        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        throw AppException.inviteInvalid();
    }
}
