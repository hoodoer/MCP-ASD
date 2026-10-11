package com.mcp_asd.burp.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/** Shared MCP detection heuristics and issue construction for the scan checks and AutoDetector. */
public final class McpIndicators {
    // Auth-related patterns in redirect Location URLs
    private static final String[] AUTH_REDIRECT_PATTERNS = {
        "doauth", "oauth", "/auth", "login", "signin", "sign-in",
        "saml", "/sso", "/cas/", "adfs", "openid", "authorize"
    };

    // MCP-related path patterns for origurl detection
    static final String[] MCP_PATH_PATTERNS = {
        "/mcp", "/sse", "/ws"
    };

    // Whitespace-tolerant: real JSON-RPC often has spaces, e.g. {"jsonrpc": "2.0", "method": "tools/list"}
    private static final Pattern JSONRPC_2_0 = Pattern.compile("\"jsonrpc\"\\s*:\\s*\"2\\.0\"");
    // Specific MCP method names, so generic JSON-RPC APIs (e.g. Ethereum "eth_call") don't match
    private static final Pattern MCP_METHOD = Pattern.compile("\"method\"\\s*:\\s*\""
            + "(initialize|notifications/initialized|tools/list|tools/call"
            + "|resources/list|resources/read|resources/templates/list|resources/subscribe"
            + "|prompts/list|prompts/get|completion/complete|logging/setLevel|ping)\"");
    private static final Pattern PROTOCOL_VERSION = Pattern.compile("\"protocolVersion\"\\s*:");

    private McpIndicators() {}

    /** True if the text is a JSON-RPC 2.0 message referencing an MCP method or the protocolVersion field. */
    public static boolean looksLikeMcpJsonRpc(String text) {
        if (text == null || text.isEmpty() || !JSONRPC_2_0.matcher(text).find()) {
            return false;
        }
        return MCP_METHOD.matcher(text).find() || PROTOCOL_VERSION.matcher(text).find();
    }

    /**
     * Check if a redirect response points to an authentication endpoint.
     */
    public static boolean isAuthRedirect(int statusCode, String locationHeader) {
        if (statusCode < 300 || statusCode > 308 || locationHeader == null || locationHeader.isEmpty()) {
            return false;
        }
        String decoded = decode(locationHeader);
        for (String pattern : AUTH_REDIRECT_PATTERNS) {
            if (decoded.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a Location header (possibly URL-encoded) contains MCP-related paths.
     * Handles origurl parameters like: ?origurl=https%3A%2F%2Fhost%2Fapi%2Fmcp
     */
    static boolean locationContainsMcpPath(String locationHeader) {
        if (locationHeader == null || locationHeader.isEmpty()) return false;
        return containsMcpPath(decode(locationHeader));
    }

    static boolean containsMcpPath(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        for (String pattern : MCP_PATH_PATTERNS) {
            if (lower.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return value.toLowerCase(Locale.ROOT);
        }
    }

    static AuditIssue issue(String name, String detail, AuditIssueConfidence confidence, HttpRequestResponse evidence) {
        return AuditIssue.auditIssue(
                name,
                detail,
                "Investigate the MCP endpoints using the MCP-ASD extension.",
                evidence.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                "The application appears to be running a Model Context Protocol (MCP) server.",
                null,
                AuditIssueSeverity.INFORMATION,
                evidence
        );
    }

    /** One issue per name per URL; repeat sightings of the same endpoint are duplicates. */
    static ConsolidationAction consolidate(AuditIssue existing, AuditIssue incoming) {
        return existing.name().equals(incoming.name()) && existing.baseUrl().equals(incoming.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }
}
