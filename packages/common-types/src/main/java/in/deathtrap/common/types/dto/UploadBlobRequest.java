package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/** Request body for uploading an encrypted asset blob to S3. */
public record UploadBlobRequest(
        @NotBlank String encryptedBlobB64,
        @Positive long sizeBytes,
        @NotBlank @Size(min = 64, max = 64) String contentHashSha256,
        @Min(1) int schemaVersion
) {}
