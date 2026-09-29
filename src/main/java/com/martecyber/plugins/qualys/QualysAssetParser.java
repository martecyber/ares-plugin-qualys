package com.martecyber.plugins.qualys;

import com.fasterxml.jackson.databind.JsonNode;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps GAV ({@code hostasset}) / CSAM ({@code asset}) search results (see {@link
 * QualysClient#fetchAssets}) into {@link ParsedAsset}s. Both modules share the same "am" API
 * response shape for the fields used here — {@code id} (stable per-tenant asset id, used for
 * external-id dedup), {@code address} (primary IP), {@code dnsHostName}/{@code netbiosName}/
 * {@code name} (hostname hints), {@code fqdn}.
 */
public class QualysAssetParser {

    private static final Logger log = LoggerFactory.getLogger(QualysAssetParser.class);

    public ParseResult parseAssets(QualysClient.AssetFetchResult fetch) {
        ParseResult result = new ParseResult();
        int emitted = 0;
        for (JsonNode asset : fetch.assets()) {
            if (emit(asset, result)) emitted++;
        }
        log.info("QualysAssetParser: {} of {} {} assets emitted (rest had no usable IP)",
            emitted, fetch.assets().size(), fetch.module());
        return result;
    }

    private boolean emit(JsonNode asset, ParseResult result) {
        String ip = asset.path("address").asText(null);
        if (ip == null || ip.isBlank()) return false;
        ip = ip.trim();

        String assetId = asset.path("id").asText(null);
        List<String> hints = new ArrayList<>();
        addIfPresent(hints, asset.path("dnsHostName").asText(null));
        addIfPresent(hints, asset.path("netbiosName").asText(null));
        addIfPresent(hints, asset.path("name").asText(null));

        String hostId = "host-" + ip;
        Map<String, Object> hostMeta = new LinkedHashMap<>();
        if (!hints.isEmpty()) hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, hints);
        if (assetId != null && !assetId.isBlank()) {
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "qualys");
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, assetId.trim());
        }
        result.addAsset(new ParsedAsset(hostId, AssetType.HOST, hostMeta));

        String ifaceId = "iface-" + ip;
        result.addAsset(new ParsedAsset(ifaceId, AssetType.INTERFACE, Map.of("ip", ip, "host", hostId)));
        result.addAsset(new ParsedAsset(ip, AssetType.IP));
        result.addLink(hostId, ifaceId, AssetLinkType.HOST_INTERFACE);
        result.addLink(ifaceId, ip, AssetLinkType.INTERFACE_IP);

        // FQDN asset only, no domain_a link — same rationale as TenableAssetParser: no DNS record
        // type/chain metadata comes with an asset-inventory record, only DNS-record-aware tools
        // (dnsx) create domain_a/domain_aaaa relationships.
        String fqdn = asset.path("fqdn").asText(null);
        if (fqdn != null && !fqdn.isBlank()) {
            result.addAsset(new ParsedAsset(fqdn.toLowerCase().trim(), AssetType.DOMAIN));
        }
        return true;
    }

    private static void addIfPresent(List<String> hints, String value) {
        if (value != null && !value.isBlank()) hints.add(value.toLowerCase().trim());
    }
}
