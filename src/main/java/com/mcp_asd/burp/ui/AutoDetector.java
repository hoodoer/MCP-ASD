package com.mcp_asd.burp.ui;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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

    public static CompletableFuture<List<DetectionResult>> detect(String host, int port) {
        return CompletableFuture.supplyAsync(() -> {
            List<DetectionResult> results = new ArrayList<>();
            OkHttpClient client = new OkHttpClient.Builder()
                    .readTimeout(2, TimeUnit.SECONDS)
                    .connectTimeout(2, TimeUnit.SECONDS)
                    .build();

            for (String path : COMMON_PATHS) {
                // 1. Check SSE
                try {
                    Request sseRequest = new Request.Builder()
                            .url("http://" + host + ":" + port + path)
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
                        }
                    }
                } catch (Exception ignored) {}

                // 2. Check WebSocket
                try {
                    Request wsProbe = new Request.Builder()
                            .url("http://" + host + ":" + port + path)
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
                        } else if (response.code() != 404 && path.contains("ws")) {
                             // If it exists (not 404) and looks like a ws path, we guess yes.
                             results.add(new DetectionResult("WebSocket", path));
                        }
                    }
                } catch (Exception ignored) {}
            }
            return results;
        });
    }
}
