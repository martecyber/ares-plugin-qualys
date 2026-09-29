package com.martecyber.plugins.qualys;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.common.ConflictException;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import com.martecyber.ares.jobs.JobView;
import com.martecyber.ares.projects.ProjectFacade;
import com.martecyber.ares.workflows.integrations.IntegrationActionDescriptor;
import com.martecyber.ares.workflows.integrations.IntegrationActionHandler;
import com.martecyber.ares.workflows.integrations.IntegrationActionResult;
import com.martecyber.ares.workflows.integrations.IntegrationInstanceDescriptor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Wires Qualys sync into {@code ACTION_INTEGRATION_CALL} — the plugin's one actual Spring-managed
 * bean, discovered by {@code com.martecyber.ares.plugins.PluginLoader} via
 * {@code META-INF/services}. Preserves the exact {@code integrationType()}/action-code/
 * {@code SOURCE_TYPE} strings core's own {@code DataSourceSyncIntegrationActionHandler}
 * ("qualys") used, so already-saved Workflow graphs and existing Detections/Assets keep working
 * unmodified once this plugin is installed.
 */
public class QualysIntegrationActionHandler implements IntegrationActionHandler {

    private static final String TYPE = "qualys";
    private static final List<IntegrationActionDescriptor> ACTIONS = List.of(
        new IntegrationActionDescriptor("SYNC_ASSETS", "Sync assets"),
        new IntegrationActionDescriptor("SYNC_VULNS", "Sync vulnerabilities"));

    private final IntegrationFacade integrationFacade;
    private final ProjectFacade projectFacade;
    private final JobFacade jobFacade;
    private final QualysSyncJobHandler syncJobHandler;

    public QualysIntegrationActionHandler(IntegrationFacade integrationFacade,
                                           ProjectFacade projectFacade,
                                           JobFacade jobFacade,
                                           IngestFacade ingestFacade,
                                           ObjectMapper objectMapper) {
        this.integrationFacade = integrationFacade;
        this.projectFacade = projectFacade;
        this.jobFacade = jobFacade;
        QualysClient client = new QualysClient(objectMapper);
        this.syncJobHandler = new QualysSyncJobHandler(jobFacade, integrationFacade,
            client, new QualysAssetParser(), new QualysVulnParser(objectMapper), ingestFacade, objectMapper);
    }

    @Override
    public String integrationType() { return TYPE; }

    @Override
    public String integrationTypeLabel() { return "Qualys"; }

    @Override
    public Set<String> supportedScopes() { return Set.of("project"); }

    @Override
    public List<IntegrationActionDescriptor> describeActions() { return ACTIONS; }

    @Override
    public List<IntegrationInstanceDescriptor> listInstances(String scopeKind, Long scopeId) {
        Long orgId = organizationIdFor(scopeId);
        if (orgId == null) return List.of();
        var byOrg = integrationFacade.list(orgId, TYPE, null, 0, 200);
        var byGrant = integrationFacade.listForProject(scopeId, orgId).stream()
            .filter(i -> TYPE.equals(i.type()))
            .toList();
        return Stream.concat(byOrg.stream(), byGrant.stream())
            .collect(Collectors.toMap(IntegrationView::id, i -> i, (a, b) -> a, LinkedHashMap::new))
            .values().stream()
            .map(i -> new IntegrationInstanceDescriptor(i.id(), i.name()))
            .toList();
    }

    @Override
    public Long start(String actionCode, Long integrationInstanceId, String scopeKind, Long scopeId, Map<String, Object> params) {
        Long projectId = scopeId;
        Long orgId = organizationIdFor(projectId);
        if (orgId == null) {
            throw new IllegalArgumentException("Project " + projectId + " not found");
        }
        String jobType = "SYNC_ASSETS".equals(actionCode) ? "TOOL_SYNC_QUALYS_ASSETS" : "TOOL_SYNC_QUALYS_VULNS";
        if (jobFacade.existsActive(projectId, jobType)) {
            throw new ConflictException("A Qualys " + ("SYNC_ASSETS".equals(actionCode) ? "asset" : "vulnerability")
                + " sync is already in progress for this project.");
        }
        var job = jobFacade.create(jobType, orgId, projectId, "{}");
        if ("SYNC_ASSETS".equals(actionCode)) {
            CompletableFuture.runAsync(() -> syncJobHandler.syncAssets(job.id(), integrationInstanceId, projectId, orgId));
        } else if ("SYNC_VULNS".equals(actionCode)) {
            CompletableFuture.runAsync(() -> syncJobHandler.syncVulns(job.id(), integrationInstanceId, projectId, orgId));
        } else {
            throw new IllegalArgumentException("Unsupported Qualys action: " + actionCode);
        }
        return job.id();
    }

    @Override
    public IntegrationActionResult checkStatus(Long refId) {
        JobView job;
        try {
            job = jobFacade.get(refId);
        } catch (Exception e) {
            return new IntegrationActionResult(IntegrationActionResult.FAILED, null, "Job " + refId + " no longer exists");
        }
        return switch (job.status()) {
            case "completed" -> new IntegrationActionResult(IntegrationActionResult.COMPLETED,
                job.result() != null ? job.result() : "{}", null);
            case "failed", "cancelled" -> new IntegrationActionResult(IntegrationActionResult.FAILED, null,
                job.error() != null ? job.error() : "Job " + job.status());
            default -> new IntegrationActionResult(IntegrationActionResult.RUNNING, null, null);
        };
    }

    private Long organizationIdFor(Long projectId) {
        try {
            return projectFacade.getOrganizationId(projectId);
        } catch (Exception e) {
            return null;
        }
    }
}
