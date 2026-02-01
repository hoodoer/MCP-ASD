package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.sse.EventSource;
import okhttp3.sse.EventSourceListener;
import okhttp3.sse.EventSources;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

public class SseTransport implements McpTransport {
    private final MontoyaApi api;
    private OkHttpClient client;
    private EventSource eventSource;
    private ConnectionConfiguration config;
    private TransportListener listener;
    private volatile String postEndpointUrl;
    private boolean forceHttp1 = false;
    private final java.util.concurrent.atomic.AtomicBoolean onOpenCalled = new java.util.concurrent.atomic.AtomicBoolean(false);

    public SseTransport(MontoyaApi api) {
        this.api = api;
    }

    public void setForceHttp1(boolean forceHttp1) {
        this.forceHttp1 = forceHttp1;
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;
        this.listener = listener;
        this.onOpenCalled.set(false);

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS); // Infinite timeout for SSE

        if (forceHttp1) {
            builder.protocols(Arrays.asList(Protocol.HTTP_1_1));
            api.logging().logToOutput("SseTransport: Forcing HTTP/1.1");
        }

        if (config.isUseMtls()) {
            configureMtls(builder, config);
        }

        client = builder.build();

        String url = "http://" + config.getHost() + ":" + config.getPort() + config.getPath();
        if (config.isUseTls() || config.isUseMtls()) {
            url = url.replace("http://", "https://");
        }

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .get()
                .addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .addHeader("Accept", "text/event-stream");

        // Add custom headers
        config.getHeaders().forEach(requestBuilder::addHeader);

        Request sseRequest = requestBuilder.build();

        EventSourceListener esListener = new EventSourceListener() {
            @Override
            public void onOpen(@NotNull EventSource eventSource, @NotNull okhttp3.Response response) {
                api.logging().logToOutput("SseTransport: Connection opened. Headers: " + response.headers());
                if (onOpenCalled.compareAndSet(false, true)) {
                    listener.onOpen();
                }
            }

            @Override
            public void onEvent(@NotNull EventSource eventSource, String id, String type, @NotNull String data) {
                // ... (existing logic)
                api.logging().logToOutput("SseTransport: Received event type: " + type + ", data: " + data);
                if ("endpoint".equals(type)) {
                    String baseUrl = (config.isUseTls() || config.isUseMtls() ? "https://" : "http://") + config.getHost() + ":" + config.getPort();
                    if (data.startsWith("http://") || data.startsWith("https://")) {
                        postEndpointUrl = data;
                    } else if (data.startsWith("/")) {
                        postEndpointUrl = baseUrl + data;
                    } else {
                        postEndpointUrl = baseUrl + (data.startsWith("/") ? "" : "/") + data;
                    }
                    api.logging().logToOutput("SseTransport: Resolved POST URL: " + postEndpointUrl);
                } else {
                    listener.onMessage(data);
                }
            }

            @Override
            public void onClosed(@NotNull EventSource eventSource) {
                api.logging().logToOutput("SseTransport: Connection closed by server.");
                listener.onClose();
            }

            @Override
            public void onFailure(@NotNull EventSource eventSource, Throwable t, okhttp3.Response response) {
                if (response != null) {
                    String body = "";
                    try {
                        body = response.body() != null ? response.body().string() : "";
                    } catch (Exception e) {
                        body = " (failed to read body)";
                    }
                    api.logging().logToError("SseTransport: Failure. Code: " + response.code() + ", Body: " + body);
                    listener.onError(new RuntimeException("HTTP " + response.code() + ": " + response.message() + "\nBody: " + body));
                } else {
                    api.logging().logToError("SseTransport: Failure. Exception: " + t.getMessage());
                    listener.onError(t);
                }
            }
        };

        EventSource.Factory factory = EventSources.createFactory(client);
        this.eventSource = factory.newEventSource(sseRequest, esListener);
        
        // Optimistic "Kickstart" - if onOpen doesn't fire in 2s, assume connected enough to try POST
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                if (onOpenCalled.compareAndSet(false, true)) {
                    api.logging().logToOutput("SseTransport: Kickstart - Optimistically triggering onOpen...");
                    listener.onOpen();
                }
            } catch (InterruptedException e) {
                // Ignore
            }
        }).start();
    }

    private void configureMtls(OkHttpClient.Builder builder, ConnectionConfiguration config) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(config.getClientCertPath())) {
                keyStore.load(fis, config.getClientCertPassword().toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, config.getClientCertPassword().toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).getTrustManagers()[0]);
            
            // Note: For testing against local servers with self-signed certs, 
            // you might need to relax hostname verification, but we'll stick to standard for now.
        } catch (Exception e) {
            api.logging().logToError("Failed to configure mTLS: " + e.getMessage());
        }
    }

    @Override
    public void send(String message) {
        if (client == null || config == null) return;
        new Thread(() -> {
            try {
                String url;
                if (postEndpointUrl != null) {
                    url = postEndpointUrl;
                } else {
                    // Wait briefly for endpoint event (race condition fix)
                    // Some servers (CoinAPI) send 'endpoint' immediately after onOpen.
                    // Others (DeepWiki) don't send it at all.
                    for (int i = 0; i < 20; i++) { // Wait up to 2 seconds
                        if (postEndpointUrl != null) break;
                        try { Thread.sleep(100); } catch (Exception ignored) {}
                    }

                    if (postEndpointUrl != null) {
                        url = postEndpointUrl;
                    } else {
                        api.logging().logToError("SseTransport: Warning - Sending message before 'endpoint' event received. Using default path.");
                        url = "http://" + config.getHost() + ":" + config.getPort() + config.getPath();
                        if (config.isUseTls() || config.isUseMtls()) {
                            url = url.replace("http://", "https://");
                        }
                    }
                }

                api.logging().logToOutput("SseTransport: Sending POST to " + url + ": " + message);
                Request.Builder requestBuilder = new Request.Builder()
                        .url(url)
                        .post(RequestBody.create(message, MediaType.get("application/json")))
                        .addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                        .addHeader("Accept", "application/json, text/event-stream");

                // Add custom headers
                config.getHeaders().forEach(requestBuilder::addHeader);

                Request request = requestBuilder.build();
                api.logging().logToOutput("SseTransport: Request Headers: " + request.headers());

                try (okhttp3.Response response = client.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        String body = "";
                        try { body = response.body().string(); } catch (Exception ignored) {}
                        api.logging().logToError("SseTransport: Error " + response.code() + ": " + body);
                    } else {
                        // Check if the server responded with data in the POST response (Non-standard MCP or specific to some implementations)
                        MediaType contentType = response.body().contentType();
                        if (contentType != null) {
                            if (contentType.type().equals("text") && contentType.subtype().equals("event-stream")) {
                                api.logging().logToOutput("SseTransport: Received SSE stream in POST response.");
                                handleSseResponse(response.body().charStream());
                            } else if (contentType.subtype().equals("json")) {
                                String json = response.body().string();
                                api.logging().logToOutput("SseTransport: Received JSON in POST response: " + json);
                                listener.onMessage(json);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("SseTransport: Send failed: " + e.getMessage());
            }
        }).start();
    }

    private void handleSseResponse(java.io.Reader reader) {
        try (java.io.BufferedReader bufferedReader = new java.io.BufferedReader(reader)) {
            String line;
            StringBuilder dataBuffer = new StringBuilder();
            while ((line = bufferedReader.readLine()) != null) {
                if (line.startsWith("data:")) {
                    dataBuffer.append(line.substring(5).trim());
                } else if (line.isEmpty()) {
                    if (dataBuffer.length() > 0) {
                        String data = dataBuffer.toString();
                        api.logging().logToOutput("SseTransport: Parsed event from POST response: " + data);
                        listener.onMessage(data);
                        dataBuffer.setLength(0);
                    }
                }
            }
            // If EOF with data pending
            if (dataBuffer.length() > 0) {
                 String data = dataBuffer.toString();
                 api.logging().logToOutput("SseTransport: Parsed event from POST response (EOF): " + data);
                 listener.onMessage(data);
            }
        } catch (Exception e) {
            api.logging().logToError("SseTransport: Failed to parse SSE from POST response: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        if (eventSource != null) {
            eventSource.cancel();
        }
        if (client != null) {
            client.dispatcher().executorService().shutdown();
        }
    }
}
