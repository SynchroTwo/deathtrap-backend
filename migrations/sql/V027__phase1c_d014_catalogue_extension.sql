-- V027: D014 — extend AssetCatalogue from 25 → 30 categories.
--
-- New entries:
--   ONLINE:  bonds, fixed_deposits
--   OFFLINE: loans_receivable, intellectual_property, loans_payable
--
-- New /locker/init calls seed all 30 automatically; existing lockers (created
-- before this migration) lack rows for the 5 new categories, so PUT
-- /locker/blob/<new_code> would 404 and the FE outbox would treat the 4xx as a
-- permanent fail (this is the same drift mode that produced D010).
--
-- This backfill inserts the missing rows for every existing locker, one
-- statement per new category. Idempotent: WHERE NOT EXISTS short-circuits on
-- re-run.

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'bonds',
    'online'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'bonds'
);

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'fixed_deposits',
    'online'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'fixed_deposits'
);

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'loans_receivable',
    'offline'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'loans_receivable'
);

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'intellectual_property',
    'offline'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'intellectual_property'
);

INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, created_at, updated_at)
SELECT
    REPLACE(gen_random_uuid()::text, '-', ''),
    lm.locker_id,
    'loans_payable',
    'offline'::asset_type_enum,
    'empty'::asset_status_enum,
    NOW(),
    NOW()
FROM locker_meta lm
WHERE NOT EXISTS (
    SELECT 1 FROM asset_index ai
    WHERE ai.locker_id = lm.locker_id AND ai.category_code = 'loans_payable'
);
