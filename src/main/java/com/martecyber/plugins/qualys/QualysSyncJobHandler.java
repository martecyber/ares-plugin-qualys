package com.martecyber.plugins.qualys;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.imports.IngestResult;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Does the actual work of a Qualys sync — VMDR Host List Detection for vuln sync, GAV/CSAM for
 * asset sync. Every Qualys integration is a fully independent tenant (its own region + own
 * username/password) — no MSSP/child-account concept exists to branch on here.
 *
 * <p>A plain object, not a Spring bean — {@link QualysIntegrationActionHandler} (the plugin's one
 * actual Spring-managed class) constructs one directly. Runs {@link #syncAssets}/
 * {@link #syncVulns} via a plain {@code CompletableFuture.runAsync(...)} instead of the original
 * {@code @Async} + self-injection trick, which needs a Spring AOP proxy this plugin's hand-
 * constructed objects don't have.
 */
public class QualysSyncJobHandler {

    private static final Logger log = LoggerFactory.getLogger(QualysSyncJobHandler.class);
    private static final String SOURCE_TYPE = "qualys";

    private final JobFacade jobFacade;
    private final IntegrationFacade integrationFacade;
    private final QualysClient qualysClient;
    private final QualysAssetParser assetParser;
    private final QualysVulnParser vulnParser;
    private final IngestFacade ingestFacade;
    private final ObjectMapper objectMapper;

    public QualysSyncJobHandler(JobFacade jobFacade,
                                 IntegrationFacade integrationFacade,
                                 QualysClient qualysClient,
                                 QualysAssetParser assetParser,
                                 QualysVulnParser vulnParser,
                                 IngestFacade ingestFacade,
                                 ObjectMapper objectMapper) {
        this.jobFacade = jobFacade;
        this.integrationFacade = integrationFacade;
        this.qualysClient = qualysClient;
        this.assetParser = assetParser;
        this.vulnParser = vulnParser;
        this.ingestFacade = ingestFacade;
        this.objectMapper = objectMapper;
    }

    // ── Asset sync (GAV/CSAM) ────────────────────────────────────────────────

    public void syncAssets(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);

            log.info("Qualys asset sync start job={} integration={} project={}", jobId, integrationId, projectId);
            setStatus(jobId, null, 10);

            QualysClient.AssetFetchResult fetch = qualysClient.fetchAssets(integration.settings(), creds);
            log.info("Qualys: {} {} assets fetched for job={}", fetch.assets().size(), fetch.module(), jobId);
            setStatus(jobId, null, 60);

            ParseResult parsed = assetParser.parseAssets(fetch);
            setStatus(jobId, null, 80);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);
            completeJob(jobId, Map.of(
                "assetsCreated", result.assetsCreated(),
                "qualysAssetsFound", fetch.assets().size(),
                "inventoryModule", fetch.module(),
                "warnings", result.warnings().size()
            ));
            log.info("Qualys asset sync done job={} found={} created={}",
                jobId, fetch.assets().size(), result.assetsCreated());

        } catch (Exception ex) {
            log.error("Qualys asset sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Vuln sync (VMDR) ──────────────────────────────────────────────────────

    public void syncVulns(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);

            log.info("Qualys vuln sync start job={} integration={} project={}", jobId, integrationId, projectId);
            setStatus(jobId, null, 5);

            List<String> pages = qualysClient.fetchVulnDetectionPages(integration.settings(), creds);
            setStatus(jobId, null, 30);

            Set<String> qids = vulnParser.collectQids(pages);
            log.info("Qualys vuln sync: {} distinct QIDs across {} page(s), resolving via KnowledgeBase",
                qids.size(), pages.size());
            setStatus(jobId, null, 40);

            Map<String, QualysClient.KbEntry> kb = qualysClient.fetchKnowledgeBase(integration.settings(), creds, qids);
            setStatus(jobId, null, 65);

            ParseResult parsed = vulnParser.parseDetections(pages, kb);
            setStatus(jobId, null, 80);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);
            completeJob(jobId, Map.of(
                "detectionsCreated", result.detectionsCreated(),
                "detectionsUpdated", result.detectionsUpdated(),
                "assetsCreated", result.assetsCreated(),
                "qidsResolved", kb.size(),
                "warnings", result.warnings().size()
            ));
            log.info("Qualys vuln sync done job={} created={} updated={} assets={}",
                jobId, result.detectionsCreated(), result.detectionsUpdated(), result.assetsCreated());

        } catch (Exception ex) {
            log.error("Qualys vuln sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void setStatus(Long jobId, String status, Integer progress) {
        try { jobFacade.update(jobId, status, progress, null, null); }
        catch (Exception e) { log.warn("job update failed: {}", e.getMessage()); }
    }

    private void completeJob(Long jobId, Map<String, Object> resultData) {
        try {
            String json = objectMapper.writeValueAsString(resultData);
            jobFacade.update(jobId, "completed", 100, json, null);
        } catch (Exception e) { log.warn("Could not complete job {}: {}", jobId, e.getMessage()); }
    }

    private void safeFailJob(Long jobId, String error) {
        try { jobFacade.update(jobId, "failed", null, null, error); }
        catch (Exception ignored) {}
    }

    private void updateLastSync(Long integrationId) {
        try {
            integrationFacade.recordSyncResult(integrationId, "success");
        } catch (Exception e) {
            log.warn("Could not update lastSyncAt for integration {}: {}", integrationId, e.getMessage());
        }
    }
}
