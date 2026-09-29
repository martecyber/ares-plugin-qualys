package com.martecyber.plugins.qualys;

import com.martecyber.ares.integrations.tools.IntegrationClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Qualys API client — covers VMDR (Host List Detection, legacy XML API, HTTP Basic auth) for
 * vulnerability sync, and GAV/CSAM (Global AssetView / CyberSecurity Asset Management, JSON,
 * gateway JWT auth) for asset sync.
 *
 * Unlike Tenable, Qualys has no MSSP/child-account concept in this integration: every Qualys
 * tenant is a fully separate subscription with its own users and its own regional platform —
 * {@link Integration#getSettings()} carries just {@code platform} (a region code, see {@link
 * #PLATFORMS}) and {@code inventoryModule} ("gav" or "csam" — a tenant normally has only one of
 * the two asset-inventory modules active). Credentials are a single Qualys username/password
 * pair, used for both the VMDR Basic-auth calls and to mint the GAV/CSAM gateway JWT.
 *
 * Platform base URLs below follow the two documented patterns (VMDR legacy API server:
 * qualysapi.qgN.apps.qualys.&lt;tld&gt;; API gateway: gateway.qgN.apps.qualys.&lt;tld&gt;) — US1 is
 * the one legacy exception without a "qgN" segment. These are best-effort from Qualys's own
 * "Platform Identification" documentation, not yet verified against a live tenant of every
 * region; if a customer's actual URL differs, confirm via Qualys support's platform-identification
 * page and adjust the table (same "verify against live data" caveat that applies to the field
 * names parsed out of VMDR/GAV/CSAM responses below).
 */
public class QualysClient implements IntegrationClient {

    private static final Logger log = LoggerFactory.getLogger(QualysClient.class);

    private record PlatformUrls(String vmdrBase, String gatewayBase) {}

    private static final Map<String, PlatformUrls> PLATFORMS = Map.ofEntries(
        Map.entry("US1",  new PlatformUrls("https://qualysapi.qualys.com",          "https://gateway.qg1.apps.qualys.com")),
        Map.entry("US2",  new PlatformUrls("https://qualysapi.qg2.apps.qualys.com", "https://gateway.qg2.apps.qualys.com")),
        Map.entry("US3",  new PlatformUrls("https://qualysapi.qg3.apps.qualys.com", "https://gateway.qg3.apps.qualys.com")),
        Map.entry("US4",  new PlatformUrls("https://qualysapi.qg4.apps.qualys.com", "https://gateway.qg4.apps.qualys.com")),
        Map.entry("EU1",  new PlatformUrls("https://qualysapi.qualys.eu",           "https://gateway.qg1.apps.qualys.eu")),
        Map.entry("EU2",  new PlatformUrls("https://qualysapi.qg2.apps.qualys.eu",  "https://gateway.qg2.apps.qualys.eu")),
        Map.entry("EU3",  new PlatformUrls("https://qualysapi.qg3.apps.qualys.it",  "https://gateway.qg3.apps.qualys.it")),
        Map.entry("UK1",  new PlatformUrls("https://qualysapi.qg1.apps.qualys.co.uk", "https://gateway.qg1.apps.qualys.co.uk")),
        Map.entry("AE1",  new PlatformUrls("https://qualysapi.qg1.apps.qualys.ae",  "https://gateway.qg1.apps.qualys.ae")),
        Map.entry("KSA1", new PlatformUrls("https://qualysapi.qg1.apps.qualysksa.com", "https://gateway.qg1.apps.qualysksa.com")),
        Map.entry("IN1",  new PlatformUrls("https://qualysapi.qg1.apps.qualys.in",  "https://gateway.qg1.apps.qualys.in")),
        Map.entry("CA1",  new PlatformUrls("https://qualysapi.qg1.apps.qualys.ca",  "https://gateway.qg1.apps.qualys.ca")),
        Map.entry("AU1",  new PlatformUrls("https://qualysapi.qg1.apps.qualys.com.au", "https://gateway.qg1.apps.qualys.com.au"))
    );
    private static final String DEFAULT_PLATFORM = "US1";

    private final HttpClient http;
    private final ObjectMapper objectMapper;

    public QualysClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    @Override
    public String supports() { return "qualys"; }

    // ── Auth check ────────────────────────────────────────────────────────────

    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        PlatformUrls urls = platformUrls(settingsJson);
        String basicAuth = basicAuthHeader(credentials);

        // VMDR probe: a truncated host-list call is the lightest authenticated VM/PC endpoint.
        HttpResponse<String> vmdrResp = http.send(
            get(urls.vmdrBase() + "/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=1", basicAuth, "text/xml"),
            HttpResponse.BodyHandlers.ofString());
        log.info("Qualys VMDR probe → HTTP {} body[0-400]={}", vmdrResp.statusCode(), snippet(vmdrResp.body(), 400));
        if (vmdrResp.statusCode() != 200)
            throw new RuntimeException("Qualys VMDR auth failed: HTTP " + vmdrResp.statusCode()
                + " — " + snippet(vmdrResp.body(), 300));

        // GAV/CSAM probe: mint a gateway JWT — this is the credential check for whichever
        // inventory module the tenant configured, since both share the same auth endpoint.
        try {
            String token = mintGatewayToken(urls.gatewayBase(), credentials);
            log.info("Qualys gateway auth OK (token length={})", token.length());
        } catch (Exception e) {
            log.warn("Qualys gateway (GAV/CSAM) auth failed — VMDR still OK, asset sync would fail: {}", e.getMessage());
        }
    }

    // ── VMDR: GET /api/2.0/fo/asset/host/vm/detection/ ─────────────────────────

    /**
     * Fetches the raw XML body of every page of the Host List Detection export. Qualys paginates
     * this legacy API via a {@code <WARNING><URL>} continuation link embedded in the response
     * rather than offset/limit — each returned string is one page's full XML body; the caller
     * (QualysVulnParser) streams and parses each page independently.
     */
    public List<String> fetchVulnDetectionPages(String settingsJson, Map<String, String> creds) throws Exception {
        PlatformUrls urls = platformUrls(settingsJson);
        String auth = basicAuthHeader(creds);
        List<String> pages = new ArrayList<>();

        String nextUrl = urls.vmdrBase()
            + "/api/2.0/fo/asset/host/vm/detection/?action=list&show_asset_id=1&truncation_limit=1000";
        int guard = 0;
        while (nextUrl != null && guard++ < 500) {
            HttpResponse<String> resp = http.send(get(nextUrl, auth, "text/xml"), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new RuntimeException("Qualys VMDR host list detection failed: HTTP " + resp.statusCode()
                    + " — " + snippet(resp.body(), 300));
            pages.add(resp.body());
            nextUrl = extractContinuationUrl(resp.body());
            if (nextUrl != null) log.debug("Qualys VMDR pagination: continuing to {}", nextUrl);
        }
        log.info("Qualys VMDR: fetched {} page(s) of host list detection", pages.size());
        return pages;
    }

    /** Pulls the continuation URL out of a Host List Detection response's trailing
     *  {@code <WARNING><URL>...</URL></WARNING>} block, when the result was truncated. */
    private static String extractContinuationUrl(String xml) {
        int warnIdx = xml.lastIndexOf("<WARNING>");
        if (warnIdx < 0) return null;
        int urlStart = xml.indexOf("<URL>", warnIdx);
        if (urlStart < 0) return null;
        int urlEnd = xml.indexOf("</URL>", urlStart);
        if (urlEnd < 0) return null;
        String url = xml.substring(urlStart + 5, urlEnd).trim();
        return url.isBlank() ? null : url.replace("&amp;", "&");
    }

    /**
     * One resolved KnowledgeBase entry — VMDR's Host List Detection API only returns QID/severity/
     * port/protocol/status per host; the human-readable title, CVE list and CVSS scores live in
     * the separate KnowledgeBase ({@code /knowledge_base/vuln/}) API and must be joined by QID.
     */
    public record KbEntry(String title, java.math.BigDecimal cvssScore, String cvssVector,
                           String cvssVersion, List<String> cveIds) {}

    /** Batches QIDs (Qualys's {@code ids} param accepts a comma-separated list, but very large
     *  syncs could exceed practical URL length) into chunks of 200 per call. */
    public Map<String, KbEntry> fetchKnowledgeBase(String settingsJson, Map<String, String> creds,
                                                     java.util.Set<String> qids) throws Exception {
        if (qids.isEmpty()) return Map.of();
        PlatformUrls urls = platformUrls(settingsJson);
        String auth = basicAuthHeader(creds);
        Map<String, KbEntry> result = new java.util.LinkedHashMap<>();
        List<String> all = new ArrayList<>(qids);
        for (int i = 0; i < all.size(); i += 200) {
            List<String> batch = all.subList(i, Math.min(i + 200, all.size()));
            String idsParam = String.join(",", batch);
            HttpResponse<String> resp = http.send(
                get(urls.vmdrBase() + "/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&ids="
                    + urlEncode(idsParam), auth, "text/xml"),
                HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new RuntimeException("Qualys KnowledgeBase lookup failed: HTTP " + resp.statusCode()
                    + " — " + snippet(resp.body(), 300));
            result.putAll(parseKnowledgeBaseXml(resp.body()));
        }
        log.info("Qualys KnowledgeBase: resolved {} of {} requested QIDs", result.size(), qids.size());
        return result;
    }

    /** Defensively handles both a flat {@code <CVSS_BASE>} tag and a nested {@code <CVSS><BASE>}
     *  shape (documentation samples disagree on which the live API actually returns) — whichever
     *  is present populates the score, so this needs no adjustment once confirmed against a real
     *  tenant, only the unused branch becomes dead code. */
    private Map<String, KbEntry> parseKnowledgeBaseXml(String xml) throws Exception {
        Map<String, KbEntry> out = new java.util.LinkedHashMap<>();
        var factory = javax.xml.stream.XMLInputFactory.newInstance();
        factory.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);
        var r = factory.createXMLStreamReader(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        String qid = null, title = null, cvssBase = null, cvss3Base = null;
        boolean inCvss = false, inCvssV3 = false, inCveList = false;
        List<String> cveIds = new ArrayList<>();
        StringBuilder text = new StringBuilder();
        java.util.Deque<String> stack = new java.util.ArrayDeque<>();

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == javax.xml.stream.XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                stack.push(tag);
                text.setLength(0);
                if ("VULN".equals(tag)) { qid = null; title = null; cvssBase = null; cvss3Base = null; cveIds = new ArrayList<>(); }
                else if ("CVSS".equals(tag)) inCvss = true;
                else if ("CVSS_V3".equals(tag)) inCvssV3 = true;
                else if ("CVE_LIST".equals(tag)) inCveList = true;
            } else if (ev == javax.xml.stream.XMLStreamConstants.CHARACTERS
                    || ev == javax.xml.stream.XMLStreamConstants.CDATA) {
                text.append(r.getText());
            } else if (ev == javax.xml.stream.XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                String val = text.toString().trim();
                switch (tag) {
                    case "QID" -> qid = val;
                    case "TITLE" -> title = val;
                    case "CVSS_BASE" -> cvssBase = val;
                    case "CVSS3_BASE" -> cvss3Base = val;
                    case "BASE" -> {
                        if (inCvssV3) cvss3Base = val; else if (inCvss) cvssBase = val;
                    }
                    case "ID" -> { if (inCveList && val.startsWith("CVE-")) cveIds.add(val); }
                    case "CVSS" -> inCvss = false;
                    case "CVSS_V3" -> inCvssV3 = false;
                    case "CVE_LIST" -> inCveList = false;
                    case "VULN" -> {
                        if (qid != null) {
                            java.math.BigDecimal score = null; String vector = null; String version = null;
                            if (cvss3Base != null && !cvss3Base.isBlank()) {
                                try { score = new java.math.BigDecimal(cvss3Base); version = "CVSS 3.1"; } catch (Exception ignored) {}
                            } else if (cvssBase != null && !cvssBase.isBlank()) {
                                try { score = new java.math.BigDecimal(cvssBase); version = "CVSS 2.0"; } catch (Exception ignored) {}
                            }
                            out.put(qid, new KbEntry(title, score, vector, version, cveIds));
                        }
                    }
                    default -> { /* other KB fields not needed */ }
                }
                if (!stack.isEmpty()) stack.pop();
                text.setLength(0);
            }
        }
        r.close();
        return out;
    }

    // ── GAV/CSAM: gateway JWT + POST /qps/rest/2.0/search/am/{hostasset|asset} ────

    /** Mints a short-lived (4h) JWT from the Qualys API gateway's /auth endpoint. */
    public String mintGatewayToken(String gatewayBase, Map<String, String> creds) throws Exception {
        String body = "username=" + urlEncode(creds.getOrDefault("username", ""))
            + "&password=" + urlEncode(creds.getOrDefault("password", ""))
            + "&token=true";
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(gatewayBase + "/auth"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "text/plain")
            .timeout(Duration.ofSeconds(20))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 201 && resp.statusCode() != 200)
            throw new RuntimeException("Qualys gateway auth failed: HTTP " + resp.statusCode()
                + " — " + snippet(resp.body(), 300));
        String token = resp.body().trim();
        if (token.isBlank()) throw new RuntimeException("Qualys gateway auth returned an empty token");
        return token;
    }

    public record AssetFetchResult(List<JsonNode> assets, String module) {}

    /**
     * Fetches all assets from the tenant's configured inventory module (GAV's {@code hostasset}
     * or CSAM's {@code asset} — same "am" module framework, different asset type per Qualys's own
     * GAV/CSAM API design), paginated via {@code lastSeenAssetId}/{@code hasMore} in the response.
     */
    public AssetFetchResult fetchAssets(String settingsJson, Map<String, String> creds) throws Exception {
        PlatformUrls urls = platformUrls(settingsJson);
        String module = inventoryModule(settingsJson);
        String assetType = "csam".equalsIgnoreCase(module) ? "asset" : "hostasset";
        String token = mintGatewayToken(urls.gatewayBase(), creds);

        List<JsonNode> out = new ArrayList<>();
        Long lastId = null;
        int guard = 0;
        while (guard++ < 1000) {
            String body = lastId == null
                ? "{\"ServiceRequest\":{\"preferences\":{\"limitResults\":300}}}"
                : "{\"ServiceRequest\":{\"filters\":{\"Criteria\":[{\"field\":\"id\",\"operator\":\"GREATER\",\"value\":\"" + lastId + "\"}]},\"preferences\":{\"limitResults\":300}}}";
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(urls.gatewayBase() + "/qps/rest/2.0/search/am/" + assetType))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(60))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            log.debug("Qualys {} search page → HTTP {} body[0-400]={}", assetType, resp.statusCode(), snippet(resp.body(), 400));
            if (resp.statusCode() != 200)
                throw new RuntimeException("Qualys " + assetType + " search failed: HTTP " + resp.statusCode()
                    + " — " + snippet(resp.body(), 300));

            JsonNode root = objectMapper.readTree(resp.body());
            JsonNode responseNode = root.path("ServiceResponse");
            JsonNode data = responseNode.path("data");
            int pageSize = 0;
            long maxId = -1;
            for (JsonNode wrapper : data) {
                JsonNode asset = wrapper.has(assetType) ? wrapper.path(assetType) : wrapper;
                out.add(asset);
                pageSize++;
                long id = asset.path("id").asLong(-1);
                if (id > maxId) maxId = id;
            }
            log.info("Qualys {} search: page {} assets, {} total so far", assetType, pageSize, out.size());
            if (pageSize == 0 || maxId < 0) break;
            lastId = maxId;
            if (pageSize < 300) break; // short page = last page
        }
        return new AssetFetchResult(out, module);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private PlatformUrls platformUrls(String settingsJson) {
        String code = platformCode(settingsJson);
        return PLATFORMS.getOrDefault(code, PLATFORMS.get(DEFAULT_PLATFORM));
    }

    private String platformCode(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank()) return DEFAULT_PLATFORM;
        try {
            String p = objectMapper.readTree(settingsJson).path("platform").asText(null);
            return (p != null && !p.isBlank()) ? p.toUpperCase() : DEFAULT_PLATFORM;
        } catch (Exception e) { return DEFAULT_PLATFORM; }
    }

    private String inventoryModule(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank()) return "gav";
        try {
            String m = objectMapper.readTree(settingsJson).path("inventoryModule").asText(null);
            return (m != null && !m.isBlank()) ? m.toLowerCase() : "gav";
        } catch (Exception e) { return "gav"; }
    }

    private static String basicAuthHeader(Map<String, String> creds) {
        String raw = creds.getOrDefault("username", "") + ":" + creds.getOrDefault("password", "");
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    private HttpRequest get(String url, String authHeader, String accept) {
        return HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", authHeader)
            .header("X-Requested-With", "ares-asm")
            .header("Accept", accept)
            .timeout(Duration.ofSeconds(90))
            .GET().build();
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String snippet(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
