package com.mcp_asd.burp.scan;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.nio.charset.StandardCharsets;

/**
 * Active probing of common MCP endpoints. Registered per host, so the Scanner runs it
 * once per host in an audit, with its own scope, scheduling and throttling.
 */
public class McpActiveScanCheck implements ActiveScanCheck {
    // Probing common endpoints (Aligned with AutoDetector, excluding root '/' to reduce noise)
    private static final String[] ENDPOINTS = {"/mcp", "/sse", "/ws", "/api/mcp", "/v1/mcp"};
    private static final int MAX_BODY_PEEK_BYTES = 4096;

    // No redirects (auth-gateway detection needs the 3xx); short timeout because SSE endpoints stream
    private static final RequestOptions PROBE_OPTIONS = RequestOptions.requestOptions()
            .withRedirectionMode(RedirectionMode.NEVER)
            .withResponseTimeout(5000);

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    @Override
    public String checkName() {
        return "MCP server detection (active probe)";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint, Http http) {
        HttpService service = baseRequestResponse.httpService();
        String hostHeader = baseRequestResponse.request().headerValue("Host");
        if (hostHeader == null || hostHeader.isEmpty()) hostHeader = service.host();

        for (String endpoint : ENDPOINTS) {
            HttpRequest probe = HttpRequest.httpRequest(service,
                    "GET " + endpoint + " HTTP/1.1\r\n" +
                    "Host: " + hostHeader + "\r\n" +
                    "Accept: text/event-stream, application/json\r\n" +
                    "User-Agent: " + USER_AGENT + "\r\n" +
                    "Connection: close\r\n" + // Try to avoid sticking
                    "\r\n");

            HttpRequestResponse result;
            try {
                result = http.sendRequest(probe, PROBE_OPTIONS);
            } catch (Exception e) {
                continue; // One failing endpoint shouldn't stop the rest
            }
            if (result == null || !result.hasResponse()) continue;

            AuditIssue issue = evaluate(endpoint, result);
            if (issue != null) {
                return AuditResult.auditResult(issue);
            }
        }
        return AuditResult.auditResult();
    }

    private static AuditIssue evaluate(String endpoint, HttpRequestResponse result) {
        HttpResponse response = result.response();
        int code = response.statusCode();
        String contentType = response.headerValue("Content-Type");

        boolean mcpHeader = response.hasHeader("MCP-Protocol-Version");
        boolean sseHeader = contentType != null && contentType.contains("text/event-stream");

        // Check the start of JSON bodies for MCP indicators
        boolean bodyIndicator = false;
        if (!mcpHeader && !sseHeader && contentType != null && contentType.contains("json")) {
            int length = Math.min(response.body().length(), MAX_BODY_PEEK_BYTES);
            String body = new String(response.body().subArray(0, length).getBytes(), StandardCharsets.UTF_8);
            bodyIndicator = body.contains("\"endpoint\":\"/mcp\"")
                    || body.contains("MCP transport")
                    || body.contains("Model Context Protocol");
        }

        // Accept 200 OK, 405 Method Not Allowed, or 410 Gone (deprecation notices)
        // Also accept ANY code if strong MCP headers are present
        if ((code == 200 || code == 405 || code == 410 || mcpHeader) && (mcpHeader || sseHeader || bodyIndicator)) {
            String evidence = "Endpoint " + endpoint + " responded with MCP indicators.";
            if (mcpHeader) evidence += " Found 'MCP-Protocol-Version' header.";
            if (sseHeader) evidence += " Found 'Content-Type: text/event-stream'.";
            if (bodyIndicator) evidence += " Found MCP-specific JSON content.";
            return McpIndicators.issue("MCP Server Discovered (Active Probe)", evidence, AuditIssueConfidence.CERTAIN, result);
        }

        // Auth gateway redirect detection: 3xx with auth-related Location header
        if (code >= 300 && code <= 308) {
            String location = response.headerValue("Location");
            if (McpIndicators.isAuthRedirect(code, location)) {
                String evidence = "Endpoint " + endpoint + " returned auth redirect (" + code + "). Location: " + location;
                if (McpIndicators.locationContainsMcpPath(location)) {
                    evidence += " Redirect target contains MCP path indicators.";
                }
                return McpIndicators.issue("MCP Endpoint Behind Auth Gateway (Active Probe)", evidence, AuditIssueConfidence.FIRM, result);
            }
        }
        return null;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return McpIndicators.consolidate(existingIssue, newIssue);
    }
}
