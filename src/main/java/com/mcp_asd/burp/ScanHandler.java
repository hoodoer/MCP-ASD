package com.mcp_asd.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ScanHandler implements HttpHandler {
    private final MontoyaApi api;
    private final GlobalSettings settings;
    // Use ConcurrentHashMap for atomic operations
    private final ConcurrentHashMap<String, Boolean> visitedDomains = new ConcurrentHashMap<>();
    private final ExecutorService probeExecutor = Executors.newFixedThreadPool(2);
    private OkHttpClient client;

    public ScanHandler(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
        rebuildClient();
    }
    
    public void shutdown() {
        probeExecutor.shutdownNow();
    }

    private void rebuildClient() {
        // Create a trust manager that does not validate certificate chains
        final TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{};
                }
            }
        };

        try {
            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(5, TimeUnit.SECONDS)
                    .followRedirects(true);

            if (settings.isProxyTrafficEnabled()) {
                String host = settings.getProxyHost();
                int port = settings.getProxyPort();
                if (host != null && !host.isEmpty() && port > 0) {
                    // api.logging().logToOutput("ScanHandler: Using Proxy " + host + ":" + port);
                    builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port)));
                } else {
                     // api.logging().logToOutput("ScanHandler: Proxy enabled but invalid host/port.");
                }
            }
            this.client = builder.build();
        } catch (Exception e) {
            api.logging().logToError("ScanHandler: Failed to create insecure SSL client: " + e.getMessage());
            this.client = new OkHttpClient(); // Fallback
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Active Detection Logic
        if (settings.isActiveDetectionEnabled()) {
            String host = requestToBeSent.httpService().host();
            
            // Check if we've already scanned this host
            if (!visitedDomains.containsKey(host)) {
                
                boolean inScope = api.scope().isInScope(requestToBeSent.url());
                
                // Proceed if "Scope Only" is disabled OR if the request is actually in scope
                if (!settings.isScopeOnlyEnabled() || inScope) {
                    
                    // Atomic check-and-set to ensure we only scan once per host
                    if (visitedDomains.putIfAbsent(host, true) == null) {
                        // api.logging().logToOutput("ScanHandler: Triggering active probe for " + host + " (InScope: " + inScope + ")");
                        
                        // Refresh client to ensure proxy settings are current
                        rebuildClient();
                        // Trigger active probe in background
                        probeExecutor.submit(() -> performActiveProbe(host, requestToBeSent.httpService().port(), requestToBeSent.httpService().secure()));
                    }
                } 
                // Note: If out of scope, we do NOT add to visitedDomains.
                // This allows subsequent requests to this host (which might be in scope) to trigger the scan.
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Passive Check Logic
        if (settings.isPassiveChecksEnabled()) {
            checkForMcpIndicators(responseReceived);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void checkForMcpIndicators(HttpResponseReceived response) {
        boolean found = false;
        String evidence = "";

        // Check Headers
        if (response.hasHeader("MCP-Protocol-Version")) {
            found = true;
            evidence = "Header 'MCP-Protocol-Version' found.";
        } else if (response.hasHeader("Mcp-Session-Id")) {
            found = true;
            evidence = "Header 'Mcp-Session-Id' found.";
        }

        // Contextual: Content-Type + Body check
        if (!found && response.hasHeader("Content-Type") && response.header("Content-Type").value().contains("text/event-stream")) {
            if (response.initiatingRequest().path().contains("/mcp") || response.initiatingRequest().path().contains("/sse")) {
                found = true;
                evidence = "Content-Type 'text/event-stream' on suspicious path.";
            }
        }

        // Body checks (JSON-RPC)
        if (!found && response.hasHeader("Content-Type") && response.header("Content-Type").value().contains("json")) {
            String body = response.bodyToString();
            if (body.contains("\"jsonrpc\":\"2.0\"")) {
                if (body.contains("\"method\":\"initialize\"") || 
                    body.contains("\"method\":\"tools/list\"") ||
                    body.contains("\"protocolVersion\":")) {
                    found = true;
                    evidence = "JSON-RPC body contains MCP methods/fields.";
                }
            }
        }

        if (found) {
            // Reconstruct HttpRequestResponse for the issue
            HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(response.initiatingRequest(), response);
            createIssue(requestResponse, "MCP Server Detected (Passive)", evidence);
        }
    }

    private void performActiveProbe(String host, int port, boolean secure) {
        // Probing common endpoints (Aligned with AutoDetector, excluding root '/' to reduce noise)
        String[] endpoints = {"/mcp", "/sse", "/ws", "/api/mcp", "/v1/mcp"};
        String protocol = secure ? "https://" : "http://";
        
        for (String endpoint : endpoints) {
            try {
                String url = protocol + host + ":" + port + endpoint;
                
                Request okRequest = new Request.Builder()
                        .url(url)
                        .header("Accept", "text/event-stream, application/json")
                        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                        .header("Connection", "close") // Try to avoid sticking
                        .get()
                        .build();

                try (Response okResponse = client.newCall(okRequest).execute()) {
                    int code = okResponse.code();
                    String contentType = okResponse.header("Content-Type", "");
                    String mcpVersion = okResponse.header("MCP-Protocol-Version");
                    
                    boolean mcpHeader = mcpVersion != null;
                    boolean sseHeader = contentType != null && contentType.contains("text/event-stream");
                    
                    // Debug log matching attempts
                    // if (code != 404) {
                    //      api.logging().logToOutput(String.format("Probe %s%s [%d] - MCP-Version: %b, SSE-Type: %b", host, endpoint, code, mcpHeader, sseHeader));
                    // }
                    
                    String bodyString = "";
                    // Read a small part of body if JSON, or just peek
                    // For SSE, we might not want to read body if header is enough, to avoid blocking
                    // If header is NOT enough, we peek.
                    if (!mcpHeader && !sseHeader && contentType != null && contentType.contains("json")) {
                        try {
                            bodyString = okResponse.peekBody(4096).string(); // Peek up to 4KB
                        } catch (Exception ignored) {}
                    }
                    
                    // Check Body for JSON indicators
                    boolean bodyIndicator = false;
                    if (!bodyString.isEmpty()) {
                        if (bodyString.contains("\"endpoint\":\"/mcp\"") || 
                            bodyString.contains("MCP transport") || 
                            bodyString.contains("Model Context Protocol")) {
                            bodyIndicator = true;
                        }
                    }
                    
                    // Accept 200 OK, 405 Method Not Allowed, or 410 Gone (deprecation notices)
                    // Also accept ANY code if strong MCP headers are present
                    if (code == 200 || code == 405 || code == 410 || mcpHeader) {
                        if (mcpHeader || sseHeader || bodyIndicator) {
                                String evidence = "Endpoint " + endpoint + " responded with MCP indicators.";
                                if (mcpHeader) evidence += " Found 'MCP-Protocol-Version' header.";
                                if (sseHeader) evidence += " Found 'Content-Type: text/event-stream'.";
                                if (bodyIndicator) evidence += " Found MCP-specific JSON content.";
                                
                                api.logging().logToOutput("FOUND MCP: " + evidence);
                                
                                // Create Burp-compatible objects for the Issue
                                burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, secure);
                                HttpRequest burpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(("GET " + endpoint + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes()));
                                
                                // Approximate response for the report
                                StringBuilder rawResponseHead = new StringBuilder();
                                rawResponseHead.append("HTTP/1.1 ").append(code).append(" Found\r\n");
                                okResponse.headers().forEach(pair -> rawResponseHead.append(pair.getFirst()).append(": ").append(pair.getSecond()).append("\r\n"));
                                rawResponseHead.append("\r\n");
                                if (!bodyString.isEmpty()) rawResponseHead.append(bodyString);
                                
                                HttpResponse burpResponse = HttpResponse.httpResponse(ByteArray.byteArray(rawResponseHead.toString().getBytes()));
                                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(burpRequest, burpResponse);
                                
                                createIssue(requestResponse, "MCP Server Discovered (Active Probe)", evidence);
                                break; 
                        }
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Active probe error: " + e.getMessage());
                // e.printStackTrace();
            }
        }
    }

    private void createIssue(HttpRequestResponse requestResponse, String name, String detail) {
        AuditIssue issue = AuditIssue.auditIssue(
                name,
                detail,
                "The application appears to be running a Model Context Protocol (MCP) server.",
                requestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.CERTAIN,
                "Investigate the MCP endpoints using the MCP-ASD extension.",
                null,
                AuditIssueSeverity.INFORMATION,
                requestResponse
        );
        api.siteMap().add(issue);
    }
}
