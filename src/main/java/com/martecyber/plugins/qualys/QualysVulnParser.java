package com.martecyber.plugins.qualys;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Maps Qualys VMDR Host List Detection API pages (see {@link QualysClient#fetchVulnDetectionPages})
 * into detections. Two-pass by design: {@link #collectQids} runs first so the caller can resolve
 * titles/CVE/CVSS via {@link QualysClient#fetchKnowledgeBase} (the Host List Detection API itself
 * only returns QID/severity/port/protocol/status per host, not the human-readable vulnerability
 * data), then {@link #parseDetections} does the real pass with that lookup available.
 *
 * Host identity: unlike the file-import {@code QualysScanResultsXmlParser} (which has no stable
 * host id in that report format), this API always returns a per-host {@code <ID>} — used as the
 * external-id dedup key via {@link AssetMetadataKeys#EXTERNAL_ID_TOOL_KEY}, exactly like Tenable's
 * asset.id.
 *
 * Same QID-collision fix as the file-import parser: the same QID can recur on one host under
 * different port/protocol (confirmed pattern in Qualys's own scan data, not format-specific), so
 * sourceTemplateId is "{QID}@{port}/{protocol}", never the bare QID.
 */
public class QualysVulnParser {

    private static final Logger log = LoggerFactory.getLogger(QualysVulnParser.class);
    private final ObjectMapper objectMapper;

    public QualysVulnParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** First pass: just the distinct QIDs across all pages, so the caller can resolve them via
     *  the KnowledgeBase API before the real parse. */
    public Set<String> collectQids(List<String> pages) throws Exception {
        Set<String> qids = new LinkedHashSet<>();
        for (String page : pages) {
            walk(page, (host, det) -> qids.add(det.qid));
        }
        return qids;
    }

    /** Second pass: builds the real ParseResult, joining each detection's QID against {@code kb}. */
    public ParseResult parseDetections(List<String> pages, Map<String, QualysClient.KbEntry> kb) throws Exception {
        ParseResult result = new ParseResult();
        int[] count = {0};
        for (String page : pages) {
            walk(page, (host, det) -> {
                emit(host, det, kb.get(det.qid), result);
                count[0]++;
            });
        }
        log.info("QualysVulnParser: {} detections parsed from {} page(s)", count[0], pages.size());
        return result;
    }

    private void emit(Host host, Detection det, QualysClient.KbEntry kb, ParseResult result) {
        if (host.ip == null || host.ip.isBlank() || det.qid == null) return;
        String hostId = "host-" + host.ip;

        Map<String, Object> hostMeta = new LinkedHashMap<>();
        if (host.dns != null && !host.dns.isBlank())
            hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, List.of(host.dns.toLowerCase().trim()));
        if (host.id != null && !host.id.isBlank()) {
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "qualys");
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, host.id.trim());
        }
        result.addAsset(new ParsedAsset(hostId, AssetType.HOST, hostMeta));

        String ifaceId = "iface-" + host.ip;
        result.addAsset(new ParsedAsset(ifaceId, AssetType.INTERFACE, Map.of("ip", host.ip, "host", hostId)));
        result.addAsset(new ParsedAsset(host.ip, AssetType.IP));
        result.addLink(hostId, ifaceId, AssetLinkType.HOST_INTERFACE);
        result.addLink(ifaceId, host.ip, AssetLinkType.INTERFACE_IP);

        String portLabel = (det.port != null && !det.port.isBlank()) ? det.port : "general";
        String proto = (det.protocol != null && !det.protocol.isBlank()) ? det.protocol.toLowerCase() : "tcp";
        String sourceTemplateId = det.qid + "@" + portLabel + "/" + proto;
        String severity = mapSeverity(det.severity);
        String title = (kb != null && kb.title() != null && !kb.title().isBlank())
            ? kb.title() : "Qualys QID " + det.qid;
        String state = mapState(det.status);

        // The complete DETECTION element Qualys returned (every tag it had, not the handful this
        // parser's own logic reads) plus the enclosing HOST's own fields for context — not the
        // KnowledgeBase title/CVE/CVSS enrichment, deliberately: that's a second, Ares-side API
        // call this parser makes on its own, not part of what Qualys itself reported for this
        // detection, so it stays out of raw_data (title/severity/CVSS already surface it
        // elsewhere on the detection itself).
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("host", host.raw);
        raw.put("detection", det.raw);
        String rawData;
        try { rawData = objectMapper.writeValueAsString(raw); } catch (Exception e) { rawData = "{}"; }

        ParsedDetection pd = new ParsedDetection(
            title, severity, null, hostId, sourceTemplateId, rawData, state);
        if (kb != null && kb.cvssScore() != null) {
            pd.setCvssScore(kb.cvssScore());
            pd.setCvssVector(kb.cvssVector());
            pd.setCvssVersion(kb.cvssVersion());
        }
        result.addDetection(pd);
    }

    /** Qualys's DETECTION severity is the same 1-5 QID scale as the Scan Results export —
     *  independent of any CVSS score that may separately come from the KnowledgeBase join. */
    private static String mapSeverity(String qualysSeverity) {
        int n;
        try { n = Integer.parseInt(qualysSeverity); } catch (Exception e) { return "info"; }
        return switch (n) {
            case 5 -> "critical";
            case 4 -> "high";
            case 3 -> "medium";
            case 2 -> "low";
            default -> "info";
        };
    }

    private static String mapState(String qualysStatus) {
        if (qualysStatus == null) return "open";
        return switch (qualysStatus.trim().toLowerCase()) {
            case "fixed" -> "fixed";
            case "re-opened", "reopened" -> "reopened";
            default -> "open"; // "New", "Active", anything else
        };
    }

    // ── XML walking ──────────────────────────────────────────────────────────

    private interface DetectionConsumer { void accept(Host host, Detection det); }

    // `raw` on both holds EVERY tag/value pair actually seen for that HOST/DETECTION element,
    // not just the ones this parser's own logic needs (id/ip/dns, qid/severity/port/...) — see
    // emit()'s rawData, which serializes these instead of a hand-picked field subset, so any
    // Qualys-reported context this parser doesn't itself act on (dates, ssl flag, results text,
    // etc.) still reaches an operator via the detection's raw_data.
    private static class Host { String id; String ip; String dns; Map<String, String> raw = new LinkedHashMap<>(); }
    private static class Detection { String qid; String type; String severity; String port; String protocol; String status; Map<String, String> raw = new LinkedHashMap<>(); }

    /** Streams one Host List Detection page, invoking {@code consumer} once per DETECTION. */
    private void walk(String xml, DetectionConsumer consumer) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        Host host = null;
        Detection det = null;
        boolean inDetection = false;
        StringBuilder text = new StringBuilder();

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                text.setLength(0);
                switch (tag) {
                    case "HOST" -> host = new Host();
                    case "DETECTION" -> { inDetection = true; det = new Detection(); }
                    default -> { /* accumulate text below */ }
                }
            } else if (ev == XMLStreamConstants.CHARACTERS || ev == XMLStreamConstants.CDATA) {
                text.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                String val = text.toString().trim();
                if (host != null && !inDetection) {
                    if (!val.isBlank() && !"HOST".equals(tag)) host.raw.put(tag, val);
                    switch (tag) {
                        case "ID" -> host.id = val;
                        case "IP" -> host.ip = val;
                        case "DNS" -> host.dns = val;
                    }
                } else if (inDetection && det != null) {
                    if (!val.isBlank() && !"DETECTION".equals(tag)) det.raw.put(tag, val);
                    switch (tag) {
                        case "QID" -> det.qid = val;
                        case "TYPE" -> det.type = val;
                        case "SEVERITY" -> det.severity = val;
                        case "PORT" -> det.port = val;
                        case "PROTOCOL" -> det.protocol = val;
                        case "STATUS" -> det.status = val;
                        case "DETECTION" -> {
                            if (host != null) consumer.accept(host, det);
                            inDetection = false;
                            det = null;
                        }
                        default -> { /* every other tag is still captured into det.raw above */ }
                    }
                }
                text.setLength(0);
            }
        }
        r.close();
    }
}
