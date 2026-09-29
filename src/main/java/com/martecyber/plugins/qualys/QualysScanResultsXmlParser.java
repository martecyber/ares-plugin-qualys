package com.martecyber.plugins.qualys;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Maps Qualys "Scan Results" XML report exports (DTD {@code scan-1.dtd}, root {@code <SCAN>} —
 * the classic per-scan XML download, distinct from the VMDR Host List Detection API used by the
 * live sync integration) into ParseResult.
 *
 * Confirmed against a real export: per {@code <IP value="{ip}" name="{dns_name?}">} block, QID
 * findings are grouped into four category wrappers — {@code <INFOS>}, {@code <SERVICES>},
 * {@code <PRACTICES>}, {@code <VULNS>} — each containing {@code <CAT value=".." port=".."
 * protocol="..">} groups. Only {@code <VULN>} and {@code <PRACTICE>} entries represent real
 * security findings (Qualys's own QID-type taxonomy); {@code <INFO>}/{@code <SERVICE>} are pure
 * fingerprinting (banners, server versions) and are not imported as detections.
 *
 * Two bugs avoided by design, both confirmed against the sample export before writing this:
 * 1. No CVSS anywhere in this format (zero "CVSS" occurrences in a real 1.3MB export) —
 *    ParsedDetection.cvssScore is deliberately left null here, never derived from Qualys's own
 *    1-5 severity scale (a different, non-CVSS scale).
 * 2. The same QID can recur on the same host under different port/protocol (confirmed: QID 15164
 *    on one host under both port=53/tcp and port=53/udp, identical title) — using the bare QID as
 *    sourceTemplateId would collide in ImportService.computeDedupHash() and silently drop the
 *    second occurrence, the same class of bug found earlier in TrivyJsonParser. Fixed by keying
 *    sourceTemplateId as "{QID}@{port}/{protocol}".
 */
public class QualysScanResultsXmlParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "qualys"; }
    @Override public String getFormatId() { return "xml"; }
    @Override public String getDisplayName() { return "Qualys Scan Results XML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".xml"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("<SCAN") && (s.contains("scan-1.dtd") || s.contains("<VULNS>") || s.contains("<INFOS>"));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(content));

        Set<String> seen = new HashSet<>();

        String currentIp = null;
        String currentHostname = null;
        String currentCatPort = null;
        String currentCatProtocol = "tcp";

        boolean inFinding = false;
        String findingCategory = null; // "VULN" or "PRACTICE"
        Finding cur = null;
        StringBuilder text = new StringBuilder();

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                text.setLength(0);

                switch (tag) {
                    case "IP" -> {
                        currentIp = r.getAttributeValue(null, "value");
                        currentHostname = r.getAttributeValue(null, "name");
                        if (currentIp != null && !currentIp.isBlank()) {
                            ScannerParserUtils.emitHostChain(currentIp.trim(), currentHostname, result, seen);
                        }
                    }
                    case "CAT" -> {
                        currentCatPort = r.getAttributeValue(null, "port");
                        String proto = r.getAttributeValue(null, "protocol");
                        currentCatProtocol = (proto != null && !proto.isBlank()) ? proto.toLowerCase() : "tcp";
                    }
                    case "VULN", "PRACTICE" -> {
                        inFinding = true;
                        findingCategory = tag;
                        cur = new Finding();
                        cur.category = tag;
                        cur.qid = r.getAttributeValue(null, "number");
                        cur.severity = r.getAttributeValue(null, "severity");
                        cur.cveIds = r.getAttributeValue(null, "cveid");
                        cur.port = currentCatPort;
                        cur.protocol = currentCatProtocol;
                        // Every attribute this element carries, not just the 3 this parser's own
                        // logic reads — see emit()'s rawData.
                        for (int i = 0; i < r.getAttributeCount(); i++) {
                            cur.raw.put(r.getAttributeLocalName(i), r.getAttributeValue(i));
                        }
                    }
                    default -> { /* INFO/SERVICE/other tags: no-op, not imported as detections */ }
                }
            } else if (ev == XMLStreamConstants.CHARACTERS || ev == XMLStreamConstants.CDATA) {
                if (inFinding) text.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                if (inFinding && cur != null) {
                    String val = text.toString().trim();
                    // Every child element's text, not just TITLE/DIAGNOSIS/SOLUTION — see
                    // emit()'s rawData. "VULN"/"PRACTICE" excluded: that's this element's own
                    // closing tag, whose accumulated text is just inter-element whitespace.
                    if (!val.isBlank() && !"VULN".equals(tag) && !"PRACTICE".equals(tag)) cur.raw.put(tag, val);
                    switch (tag) {
                        case "TITLE" -> cur.title = val;
                        case "DIAGNOSIS" -> cur.diagnosis = val;
                        case "SOLUTION" -> cur.solution = val;
                    }
                }
                if (("VULN".equals(tag) || "PRACTICE".equals(tag)) && inFinding) {
                    emit(currentIp, currentHostname, cur, result);
                    inFinding = false;
                    findingCategory = null;
                    cur = null;
                }
                text.setLength(0);
            }
        }
        r.close();
        return result;
    }

    private void emit(String ip, String hostname, Finding f, ParseResult result) {
        if (ip == null || ip.isBlank() || f == null || f.qid == null) return;

        String portLabel = (f.port != null && !f.port.isBlank()) ? f.port : "general";
        String sourceTemplateId = f.qid + "@" + portLabel + "/" + f.protocol;
        String severity = mapSeverity(f.severity);
        String title = (f.title != null && !f.title.isBlank()) ? f.title : "Qualys QID " + f.qid;

        // The complete <VULN>/<PRACTICE> element Qualys's export reported (every attribute and
        // child tag it had, not the handful this parser's own logic reads), plus the enclosing
        // <IP>/<CAT> context — not a hand-picked field subset.
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("ip", ip);
        raw.put("hostname", hostname);
        raw.put("category", f.category);
        raw.put("finding", f.raw);
        String rawData;
        try { rawData = MAPPER.writeValueAsString(raw); } catch (Exception e) { rawData = "{}"; }

        String assetIdentifier = "host-" + ip;
        result.addDetection(new ParsedDetection(
            title, severity, f.diagnosis, assetIdentifier, sourceTemplateId, rawData));
    }

    /** Qualys's own QID severity scale is 1 (Minimal) .. 5 (Urgent) — not CVSS, mapped
     *  independently rather than forced through {@link ScannerParserUtils#cvssToSeverity}. */
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

    /** Transient per-&lt;VULN&gt;/&lt;PRACTICE&gt; accumulator. {@code raw} holds every attribute
     *  and child-element value actually seen for this finding, independent of the specific
     *  fields (qid/severity/cveIds/...) this parser's own logic reads out of it — see emit(). */
    private static class Finding {
        String category; // "VULN" or "PRACTICE"
        String qid;
        String severity;
        String cveIds;
        String port;
        String protocol;
        String title;
        String diagnosis;
        String solution;
        Map<String, String> raw = new LinkedHashMap<>();
    }
}
