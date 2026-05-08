package in.deathtrap.locker.config;

import in.deathtrap.common.types.enums.AssetType;
import java.util.List;

/** Canonical list of the 24 predefined asset categories seeded at locker initialisation. */
public final class AssetCatalogue {

    public static final List<AssetEntry> ALL = List.of(
            new AssetEntry("bank_accounts",             AssetType.ONLINE),
            new AssetEntry("mutual_funds",              AssetType.ONLINE),
            new AssetEntry("demat_stocks",              AssetType.ONLINE),
            new AssetEntry("provident_fund",            AssetType.ONLINE),
            new AssetEntry("insurance_policies",        AssetType.ONLINE),
            new AssetEntry("crypto_wallets",            AssetType.ONLINE),
            new AssetEntry("digital_payments",          AssetType.ONLINE),
            new AssetEntry("email_accounts",            AssetType.ONLINE),
            new AssetEntry("social_media",              AssetType.ONLINE),
            new AssetEntry("cloud_storage",             AssetType.ONLINE),
            new AssetEntry("domain_websites",           AssetType.ONLINE),
            new AssetEntry("online_subscriptions",      AssetType.ONLINE),
            new AssetEntry("will_testament",            AssetType.OFFLINE),
            new AssetEntry("property_real_estate",      AssetType.OFFLINE),
            new AssetEntry("vehicle",                   AssetType.OFFLINE),
            new AssetEntry("jewellery_valuables",       AssetType.OFFLINE),
            new AssetEntry("bank_locker",               AssetType.OFFLINE),
            new AssetEntry("agricultural_land",         AssetType.OFFLINE),
            new AssetEntry("business_interests",        AssetType.OFFLINE),
            new AssetEntry("nps_pension",               AssetType.OFFLINE),
            new AssetEntry("gratuity_superannuation",   AssetType.OFFLINE),
            new AssetEntry("personal_documents",        AssetType.OFFLINE),
            new AssetEntry("unorganised_notes",         AssetType.OFFLINE),
            new AssetEntry("cash_physical",             AssetType.OFFLINE)
    );

    public record AssetEntry(String categoryCode, AssetType assetType) {}

    private AssetCatalogue() {}
}
