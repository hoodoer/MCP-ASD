package com.mcp_asd.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcp_asd.burp.scan.McpIndicators;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class AutoDetector {
    private static final List<String> COMMON_PATHS = Arrays.asList("/mcp", "/sse", "/ws", "/", "/api/mcp", "/v1/mcp");

    public static class DetectionResult {
        public String transport; // "SSE" or "WebSocket"
        public String path;

        public DetectionResult(String transport, String path) {
            this.transport = transport;
            this.path = path;
        }
        
        @Override
        public String toString() {
            return transport + " at " + path;
        }
    }

    // Probes go through Burp's HTTP stack (upstream proxy, session handling, Burp's TLS settings).
    // HTTP/1.1 because the WebSocket probe relies on Upgrade; short timeout because SSE endpoints stream.
    private static final RequestOptions PROBE_OPTIONS = RequestOptions.requestOptions()
            .withHttpMode(HttpMode.HTTP_1)
            .withRedirectionMode(RedirectionMode.NEVER)
            .withResponseTimeout(5000);

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    public static CompletableFuture<List<DetectionResult>> detect(MontoyaApi api, String host, int port, boolean useTls) {
        return CompletableFuture.supplyAsync(() -> {
            List<DetectionResult> results = new ArrayList<>();
            HttpService service = HttpService.httpService(host, port, useTls);
            boolean defaultPort = (useTls && port == 443) || (!useTls && port == 80);
            String hostHeader = defaultPort ? host : host + ":" + port;

            for (String path : COMMON_PATHS) {
                // 1. Check SSE
                HttpResponse response = probe(api, service, "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + hostHeader + "\r\n" +
                        "User-Agent: " + USER_AGENT + "\r\n" +
                        "Accept: text/event-stream\r\n\r\n");
                if (response != null) {
                    int code = response.statusCode();
                    if (code == 200) {
                        String contentType = response.headerValue("Content-Type");
                        if (contentType != null && contentType.contains("text/event-stream")) {
                            results.add(new DetectionResult("SSE", path));
                            continue; // Don't check WS for this path if it's already SSE
                        }
                    } else if (code == 401 || code == 403) {
                        // If we get an auth error, the endpoint exists!
                        results.add(new DetectionResult("SSE (Auth Required)", path));
                        continue;
                    } else if (code >= 300 && code <= 308) {
                        if (McpIndicators.isAuthRedirect(code, response.headerValue("Location"))) {
                            results.add(new DetectionResult("SSE (Auth Gateway)", path));
                            continue;
                        }
                    } else {
                        api.logging().logToOutput("AutoDetector SSE Fail [" + path + "]: Code " + code);
                    }
                }

                // 2. Check WebSocket
                response = probe(api, service, "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + hostHeader + "\r\n" +
                        "User-Agent: " + USER_AGENT + "\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                        "Sec-WebSocket-Version: 13\r\n\r\n");
                if (response != null && path.contains("ws")) {
                    int code = response.statusCode();
                    // 101 Switching Protocols = Success
                    // 426 Upgrade Required = Valid endpoint
                    // 401/403 = Valid endpoint, auth required
                    if (code == 101 || code == 426) {
                        results.add(new DetectionResult("WebSocket", path));
                    } else if (code == 401 || code == 403) {
                        results.add(new DetectionResult("WebSocket (Auth Required)", path));
                    } else if (code >= 300 && code <= 308) {
                        if (McpIndicators.isAuthRedirect(code, response.headerValue("Location"))) {
                            results.add(new DetectionResult("WebSocket (Auth Gateway)", path));
                        }
                    } else if (code != 404) {
                        // If it exists (not 404) and looks like a ws path, we guess yes.
                        results.add(new DetectionResult("WebSocket", path));
                    }
                }
            }
            return results;
        });
    }

    /** Sends one probe; returns null if there was no response (connection failure or timeout). */
    private static HttpResponse probe(MontoyaApi api, HttpService service, String rawRequest) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(service, rawRequest), PROBE_OPTIONS);
            return rr.hasResponse() ? rr.response() : null;
        } catch (Exception e) {
            api.logging().logToOutput("AutoDetector probe error [" + service + "]: " + e.getMessage());
            return null;
        }
    }
}
