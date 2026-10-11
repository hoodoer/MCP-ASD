package com.mcp_asd.burp.scan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.mcp_asd.burp.GlobalSettings;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Passive detection of MCP servers from observed traffic (headers, JSON-RPC bodies,
 * auth-gateway redirects from MCP paths). Registered per request.
 */
public class McpPassiveScanCheck implements PassiveScanCheck {
    // MCP handshake markers appear at the start of a JSON-RPC message; don't scan huge bodies
    private static final int MAX_BODY_SCAN_BYTES = 64 * 1024;

    private final GlobalSettings settings;

    public McpPassiveScanCheck(GlobalSettings settings) {
        this.settings = settings;
    }

    @Override
    public String checkName() {
        return "MCP server detection (passive)";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        if (!settings.isPassiveChecksEnabled() || !requestResponse.hasResponse()) {
            return AuditResult.auditResult();
        }

        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        String evidence = null;

        // Check Headers
        if (response.hasHeader("MCP-Protocol-Version")) {
            evidence = "Header 'MCP-Protocol-Version' found.";
        } else if (response.hasHeader("Mcp-Session-Id")) {
            evidence = "Header 'Mcp-Session-Id' found.";
        }

        String contentType = response.headerValue("Content-Type");

        // Contextual: Content-Type + path check
        if (evidence == null && contentType != null && contentType.contains("text/event-stream")) {
            if (request.path().contains("/mcp") || request.path().contains("/sse")) {
                evidence = "Content-Type 'text/event-stream' on suspicious path.";
            }
        }

        // JSON-RPC in the response body (first 64 KB only, so a huge body can't stall the scanner thread)
        if (evidence == null && contentType != null && contentType.contains("json")
                && McpIndicators.looksLikeMcpJsonRpc(firstBytes(response.body()))) {
            evidence = "JSON-RPC response body contains MCP methods/fields.";
        }

        // JSON-RPC in the request body: catches client-side MCP traffic where the response is opaque
        // (e.g. an SSE stream, or a bare {"status":"accepted"})
        if (evidence == null) {
            String requestContentType = request.headerValue("Content-Type");
            if (requestContentType != null && requestContentType.contains("json")
                    && McpIndicators.looksLikeMcpJsonRpc(firstBytes(request.body()))) {
                evidence = "JSON-RPC request body contains MCP methods.";
            }
        }

        if (evidence != null) {
            return AuditResult.auditResult(McpIndicators.issue(
                    "MCP Server Detected (Passive)", evidence, AuditIssueConfidence.CERTAIN, requestResponse));
        }

        // Auth gateway redirect detection: 3xx redirect from MCP paths or with MCP paths in origurl
        int statusCode = response.statusCode();
        String location = response.headerValue("Location");
        if (statusCode >= 300 && statusCode <= 308 && McpIndicators.isAuthRedirect(statusCode, location)) {
            String requestPath = request.path().toLowerCase(Locale.ROOT);
            String authEvidence = null;
            if (McpIndicators.containsMcpPath(requestPath)) {
                authEvidence = "Auth redirect (" + statusCode + ") from MCP path '" + requestPath + "'. Location: " + location;
            } else if (McpIndicators.locationContainsMcpPath(location)) {
                authEvidence = "Auth redirect (" + statusCode + ") with MCP path in redirect target. Location: " + location;
            }
            if (authEvidence != null) {
                return AuditResult.auditResult(McpIndicators.issue(
                        "MCP Endpoint Behind Auth Gateway (Passive)", authEvidence, AuditIssueConfidence.FIRM, requestResponse));
            }
        }

        return AuditResult.auditResult();
    }

    /** First 64 KB of a body as UTF-8 text; bounds the work the regex scan does. */
    private static String firstBytes(ByteArray body) {
        int end = Math.min(body.length(), MAX_BODY_SCAN_BYTES);
        return end <= 0 ? "" : new String(body.subArray(0, end).getBytes(), StandardCharsets.UTF_8);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return McpIndicators.consolidate(existingIssue, newIssue);
    }
}
