package in.deathtrap.common.types.dto;

import java.time.Instant;

/** Response body for POST /recovery/blob.
 *  Per docs/RECOVERY_BLOB_FORMAT.md §10 / BACKEND_CHANGES §3.1.
 *  - blobId: echo of the client-generated UUID v4 stored in recovery_blobs.blob_id.
 *  - version: monotonic per-creator counter — rank by recovery_blobs.created_at
 *    (so the first ever recovery blob a creator uploads is version=1, the
 *    second is version=2, etc.). Independent of locker blob version.
 *  - uploadedAt: server's timestamp for when the row landed. */
public record StoreBlobResponse(
        String blobId,
        int version,
        Instant uploadedAt
) {}
