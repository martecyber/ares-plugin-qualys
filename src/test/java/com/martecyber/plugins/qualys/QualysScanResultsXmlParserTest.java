package com.martecyber.plugins.qualys;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link QualysScanResultsXmlParser}: the host-chain emission per &lt;IP&gt; block,
 *  &lt;INFO&gt;/&lt;SERVICE&gt; fingerprinting entries never becoming detections (only
 *  &lt;VULN&gt;/&lt;PRACTICE&gt; do), the Qualys 1-5 severity scale mapping, the
 *  {@code "{QID}@{port}/{protocol}"} sourceTemplateId that keeps the same QID recurring on
 *  different ports from colliding, and the "general" port fallback. */
class QualysScanResultsXmlParserTest {

    private final QualysScanResultsXmlParser parser = new QualysScanResultsXmlParser();

    private ParseResult parse(String xml) throws Exception {
        return parser.parse(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static final String XML = """
        <?xml version="1.0"?>
        <!DOCTYPE SCAN SYSTEM "scan-1.dtd">
        <SCAN>
          <IP value="10.0.0.1" name="host1.example.com">
            <INFOS>
              <CAT port="21" protocol="tcp">
                <INFO number="12345"><TITLE>FTP Banner</TITLE></INFO>
              </CAT>
            </INFOS>
            <VULNS>
              <CAT port="443" protocol="tcp">
                <VULN number="38170" severity="5">
                  <TITLE>SSL Vulnerability</TITLE>
                  <DIAGNOSIS>Detailed diagnosis text.</DIAGNOSIS>
                  <SOLUTION>Apply patch.</SOLUTION>
                </VULN>
              </CAT>
              <CAT port="53" protocol="udp">
                <VULN number="15164" severity="2" cveid="CVE-2024-0001">
                  <TITLE>DNS issue</TITLE>
                  <DIAGNOSIS>DNS diag</DIAGNOSIS>
                </VULN>
              </CAT>
            </VULNS>
            <PRACTICES>
              <CAT protocol="tcp">
                <PRACTICE number="15164" severity="3">
                  <TITLE>DNS issue</TITLE>
                  <DIAGNOSIS>Practice diag on a different port</DIAGNOSIS>
                </PRACTICE>
              </CAT>
            </PRACTICES>
          </IP>
        </SCAN>
        """;

    @Test
    void validateRequiresScanRootAndAKnownMarker() {
        assertTrue(parser.validate(XML.getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<html/>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void emitsHostChainWithHostnameHintPerIpBlock() throws Exception {
        ParseResult result = parse(XML);
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.HOST) && a.getIdentifier().equals("host-10.0.0.1")
            && List.of("host1.example.com").equals(a.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY))));
    }

    @Test
    void infoEntriesNeverBecomeDetections() throws Exception {
        ParseResult result = parse(XML);
        assertTrue(result.getDetections().stream().noneMatch(d -> "FTP Banner".equals(d.getTitle())));
    }

    @Test
    void vulnEntryMapsSeverityTitleDiagnosisAndAssetIdentifier() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> "SSL Vulnerability".equals(x.getTitle())).findFirst().orElseThrow();
        assertEquals("critical", d.getSeverity());
        assertEquals("Detailed diagnosis text.", d.getDescription());
        assertEquals("host-10.0.0.1", d.getAssetIdentifier());
        assertEquals("38170@443/tcp", d.getSourceTemplateId());
        assertTrue(d.getRawData().contains("Apply patch."));
    }

    @Test
    void sameQidOnDifferentPortsProducesDistinctTemplateIdsAndBothDetections() throws Exception {
        var detections = parse(XML).getDetections().stream()
            .filter(d -> "DNS issue".equals(d.getTitle())).toList();
        assertEquals(2, detections.size());
        assertEquals("15164@53/udp", detections.get(0).getSourceTemplateId());
        // No port attribute on the PRACTICE's <CAT> — falls back to "general".
        assertEquals("15164@general/tcp", detections.get(1).getSourceTemplateId());
    }

    @Test
    void cveIdIsCapturedInRawDataWhenPresent() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> "DNS issue".equals(x.getTitle()) && x.getSourceTemplateId().contains("udp")).findFirst().orElseThrow();
        assertTrue(d.getRawData().contains("CVE-2024-0001"));
    }

    @Test
    void severityScaleCoversTheFullOneToFiveRangeWithNonNumericFallingBackToInfo() throws Exception {
        String xml = """
            <SCAN><IP value="10.0.0.2"><VULNS>
              <CAT port="1" protocol="tcp"><VULN number="1" severity="1"><TITLE>A</TITLE></VULN></CAT>
              <CAT port="2" protocol="tcp"><VULN number="2" severity="4"><TITLE>B</TITLE></VULN></CAT>
              <CAT port="3" protocol="tcp"><VULN number="3" severity="not-a-number"><TITLE>C</TITLE></VULN></CAT>
            </VULNS></IP></SCAN>
            """;
        var detections = parse(xml).getDetections();
        assertEquals("info", detections.get(0).getSeverity());
        assertEquals("high", detections.get(1).getSeverity());
        assertEquals("info", detections.get(2).getSeverity());
    }

    @Test
    void vulnEntryWithoutAQidNumberIsNotEmitted() throws Exception {
        String xml = """
            <SCAN><IP value="10.0.0.3"><VULNS>
              <CAT port="1" protocol="tcp"><VULN severity="5"><TITLE>No QID</TITLE></VULN></CAT>
            </VULNS></IP></SCAN>
            """;
        assertTrue(parse(xml).getDetections().isEmpty());
    }

    @Test
    void ipBlockWithoutAValueAttributeEmitsNothingForItsFindings() throws Exception {
        String xml = """
            <SCAN><IP name="mystery-host"><VULNS>
              <CAT port="1" protocol="tcp"><VULN number="1" severity="5"><TITLE>X</TITLE></VULN></CAT>
            </VULNS></IP></SCAN>
            """;
        ParseResult result = parse(xml);
        assertTrue(result.getAssets().isEmpty());
        assertTrue(result.getDetections().isEmpty());
    }

    @Test
    void titleFallsBackToQidWhenMissing() throws Exception {
        String xml = """
            <SCAN><IP value="10.0.0.4"><VULNS>
              <CAT port="1" protocol="tcp"><VULN number="999" severity="5"></VULN></CAT>
            </VULNS></IP></SCAN>
            """;
        assertEquals("Qualys QID 999", parse(xml).getDetections().get(0).getTitle());
    }
}
