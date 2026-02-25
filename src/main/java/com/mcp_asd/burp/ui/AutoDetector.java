package com.mcp_asd.burp.ui;

import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class AutoDetector {
    private static final List<String> COMMON_PATHS = Arrays.asList("/mcp", "/sse", "/ws", "/", "/api/mcp", "/v1/mcp");

    private static final String[] AUTH_REDIRECT_PATTERNS = {
        "doauth", "oauth", "/auth", "login", "signin", "sign-in",
        "saml", "/sso", "/cas/", "adfs", "openid", "authorize"
    };

    private static boolean isAuthRedirect(int statusCode, String locationHeader) {
        if (statusCode < 300 || statusCode > 308 || locationHeader == null || locationHeader.isEmpty()) {
            return false;
        }
        String decoded;
        try {
            decoded = URLDecoder.decode(locationHeader, "UTF-8").toLowerCase();
        } catch (Exception e) {
            decoded = locationHeader.toLowerCase();
        }
        for (String pattern : AUTH_REDIRECT_PATTERNS) {
            if (decoded.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

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

    public static CompletableFuture<List<DetectionResult>> detect(String host, int port, boolean useTls) {
        return CompletableFuture.supplyAsync(() -> {
            List<DetectionResult> results = new ArrayList<>();
            OkHttpClient client = new OkHttpClient.Builder()
                    .protocols(Arrays.asList(Protocol.HTTP_1_1))
                    .readTimeout(5, TimeUnit.SECONDS)
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .followRedirects(false)
                    .build();
            
            String protocol = useTls ? "https://" : "http://";

            for (String path : COMMON_PATHS) {
                // 1. Check SSE
                try {
                    Request sseRequest = new Request.Builder()
                            .url(protocol + host + ":" + port + path)
                            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                            .header("Accept", "text/event-stream")
                            .get()
                            .build();
                    try (Response response = client.newCall(sseRequest).execute()) {
                        if (response.code() == 200) {
                            String contentType = response.header("Content-Type", "");
                            if (contentType != null && contentType.contains("text/event-stream")) {
                                results.add(new DetectionResult("SSE", path));
                                continue; // Don't check WS for this path if it's already SSE
                            }
                        } else if (response.code() == 401 || response.code() == 403) {
                            // If we get an auth error, the endpoint exists!
                            results.add(new DetectionResult("SSE (Auth Required)", path));
                            continue;
                        } else if (response.code() >= 300 && response.code() <= 308) {
                            String location = response.header("Location", "");
                            if (isAuthRedirect(response.code(), location)) {
                                results.add(new DetectionResult("SSE (Auth Gateway)", path));
                                continue;
                            }
                        } else {
                            System.out.println("AutoDetector SSE Fail [" + path + "]: Code " + response.code());
                        }
                    }
                } catch (Exception e) {
                    System.out.println("AutoDetector SSE Error [" + path + "]: " + e.getMessage());
                }

                // 2. Check WebSocket
                try {
                    Request wsProbe = new Request.Builder()
                            .url(protocol + host + ":" + port + path)
                            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                            .header("Connection", "Upgrade")
                            .header("Upgrade", "websocket")
                            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                            .header("Sec-WebSocket-Version", "13")
                            .get()
                            .build();
                    try (Response response = client.newCall(wsProbe).execute()) {
                        // 101 Switching Protocols = Success
                        // 426 Upgrade Required = Valid endpoint
                        // 401/403 = Valid endpoint, auth required
                        if (response.code() == 101 || response.code() == 426) {
                            if (path.contains("ws")) { 
                                results.add(new DetectionResult("WebSocket", path));
                            }
                        } else if (response.code() == 401 || response.code() == 403) {
                             if (path.contains("ws")) {
                                 results.add(new DetectionResult("WebSocket (Auth Required)", path));
                             }
                        } else if (response.code() >= 300 && response.code() <= 308 && path.contains("ws")) {
                             String location = response.header("Location", "");
                             if (isAuthRedirect(response.code(), location)) {
                                 results.add(new DetectionResult("WebSocket (Auth Gateway)", path));
                             }
                        } else if (response.code() != 404 && path.contains("ws")) {
                             // If it exists (not 404) and looks like a ws path, we guess yes.
                             results.add(new DetectionResult("WebSocket", path));
                        }
                    }
                } catch (Exception e) {
                     System.out.println("AutoDetector WS Error [" + path + "]: " + e.getMessage());
                }
            }
            return results;
        });
    }
}
