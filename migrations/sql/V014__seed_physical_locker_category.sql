-- V014: Seed the physical_locker category (E002).
--
-- AssetCatalogue.ALL grows from 24 -> 25 entries with physical_locker added
-- as an OFFLINE category. New /locker/init calls seed it automatically;
-- existing lockers (created before this migration) lack the asset_index row,
-- so PUT /locker/blob/physical_locker would 404. This backfill inserts the
-- missing row for every existing locker.
--
-- Idempotent: WHERE NOT EXISTS short-circuits on re-run.

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'physical_locker',
    'offline'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'physical_locker'
);
