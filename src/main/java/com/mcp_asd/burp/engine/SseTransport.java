package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.sse.EventSource;
import okhttp3.sse.EventSourceListener;
import okhttp3.sse.EventSources;
import org.jetbrains.annotations.NotNull;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL; // Add URL import
import java.util.Arrays;
import java.util.concurrent.CountDownLatch; // Add CountDownLatch import
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

public class SseTransport implements McpTransport {
    private final MontoyaApi api;
    private final GlobalSettings settings;
    private OkHttpClient client;
    private EventSource eventSource;
    private ConnectionConfiguration config;
    private TransportListener listener;
    private volatile String postEndpointUrl;
    private boolean forceHttp1 = false;
    private final java.util.concurrent.atomic.AtomicBoolean onOpenCalled = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final CountDownLatch endpointLatch = new CountDownLatch(1); // Add Latch

    public SseTransport(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
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

        // --- SSL Configuration ---
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}
                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{}; }
                }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);

        } catch (Exception e) {
            api.logging().logToError("SseTransport: Failed to create insecure SSL context: " + e.getMessage());
        }
        // -------------------------

        if (forceHttp1) {
            builder.protocols(Arrays.asList(Protocol.HTTP_1_1));
            api.logging().logToOutput("SseTransport: Forcing HTTP/1.1");
        }

        if (config.isUseMtls()) {
            configureMtls(builder, config);
        }
        
        if (settings != null && settings.isProxyTrafficEnabled()) {
             String host = settings.getProxyHost();
             int port = settings.getProxyPort();
             if (host != null && !host.isEmpty() && port > 0) {
                 api.logging().logToOutput("SseTransport: Using proxy " + host + ":" + port);
                 builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port)));
             }
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
                try {
                    api.logging().logToOutput("SseTransport: Connection opened. Headers: " + response.headers());
                } catch (Exception ignored) {} // Catch NPE during unload
                
                if (onOpenCalled.compareAndSet(false, true)) {
                    listener.onOpen();
                }
            }

            @Override
            public void onEvent(@NotNull EventSource eventSource, String id, String type, @NotNull String data) {
                try {
                    api.logging().logToOutput("SseTransport: Received event type: " + type + ", data: " + data);
                } catch (Exception ignored) {}

                if ("endpoint".equals(type)) {
                    String baseUrl = (config.isUseTls() || config.isUseMtls() ? "https://" : "http://") + config.getHost() + ":" + config.getPort();
                    String candidateUrl;
                    
                    if (data.startsWith("/")) {
                        candidateUrl = baseUrl + data;
                    } else if (data.startsWith("http://") || data.startsWith("https://")) {
                        candidateUrl = data;
                    } else {
                        candidateUrl = baseUrl + (data.startsWith("/") ? "" : "/") + data;
                    }

                    // Security Check: SSRF Prevention
                    try {
                        URL original = new URL(baseUrl);
                        URL candidate = new URL(candidateUrl);
                        
                        if (!original.getHost().equalsIgnoreCase(candidate.getHost()) || 
                            original.getPort() != candidate.getPort()) {
                            try {
                                api.logging().logToError("SECURITY WARNING: Server attempted to redirect POST endpoint to external/different host: " + candidateUrl + ". Ignoring.");
                            } catch (Exception ignored) {}
                            // Fallback to default
                            postEndpointUrl = baseUrl + config.getPath(); 
                        } else {
                            postEndpointUrl = candidateUrl;
                            try {
                                api.logging().logToOutput("SseTransport: Resolved POST URL: " + postEndpointUrl);
                            } catch (Exception ignored) {}
                        }
                    } catch (Exception e) {
                        try {
                            api.logging().logToError("Failed to validate endpoint URL: " + e.getMessage());
                        } catch (Exception ignored) {}
                        postEndpointUrl = baseUrl + config.getPath();
                    }
                    
                    endpointLatch.countDown(); // Signal readiness
                } else {
                    listener.onMessage(data);
                }
            }

            @Override
            public void onClosed(@NotNull EventSource eventSource) {
                try {
                    api.logging().logToOutput("SseTransport: Connection closed by server.");
                } catch (Exception ignored) {}
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
                    try {
                        api.logging().logToError("SseTransport: Failure. Code: " + response.code() + ", Body: " + body);
                    } catch (Exception ignored) {}
                    listener.onError(new RuntimeException("HTTP " + response.code() + ": " + response.message() + "\nBody: " + body));
                } else {
                    try {
                        api.logging().logToError("SseTransport: Failure. Exception: " + t.getMessage());
                    } catch (Exception ignored) {}
                    listener.onError(t);
                }
            }
        };

        EventSource.Factory factory = EventSources.createFactory(client);
        this.eventSource = factory.newEventSource(sseRequest, esListener);
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
                    // Wait for endpoint event using Latch (max 2 seconds)
                    try {
                        endpointLatch.await(2000, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException ignored) {}

                    if (postEndpointUrl != null) {
                        url = postEndpointUrl;
                    } else {
                        api.logging().logToError("SseTransport: Warning - Sending message before 'endpoint' event received (or timed out). Using default path.");
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

                // Use a client with a read timeout for POSTs to avoid hanging on stuck streams
                OkHttpClient postClient = client.newBuilder()
                        .readTimeout(30, TimeUnit.SECONDS)
                        .build();

                try (okhttp3.Response response = postClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        String body = "";
                        try { body = response.body().string(); } catch (Exception ignored) {}
                        api.logging().logToError("SseTransport: Error " + response.code() + ": " + body);
                    } else {
                        // Check if the server responded with data in the POST response (Non-standard MCP or specific to some implementations)
                        MediaType contentType = response.body().contentType();
                        if (contentType != null) {
                            if (contentType.type().equals("text") && contentType.subtype().equals("event-stream")) {
                                try {
                                    api.logging().logToOutput("SseTransport: Received SSE stream in POST response.");
                                } catch (Exception ignored) {}
                                handleSseResponse(response.body().charStream());
                            } else if (contentType.subtype().equals("json")) {
                                String json = response.body().string();
                                try {
                                    api.logging().logToOutput("SseTransport: Received JSON in POST response: " + json);
                                } catch (Exception ignored) {}
                                listener.onMessage(json);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                try {
                    api.logging().logToError("SseTransport: Send failed: " + e.getMessage());
                } catch (Exception ignored) {}
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
                        try {
                            api.logging().logToOutput("SseTransport: Parsed event from POST response: " + data);
                        } catch (Exception ignored) {}
                        listener.onMessage(data);
                        dataBuffer.setLength(0);
                    }
                }
            }
            // If EOF with data pending
            if (dataBuffer.length() > 0) {
                 String data = dataBuffer.toString();
                 try {
                     api.logging().logToOutput("SseTransport: Parsed event from POST response (EOF): " + data);
                 } catch (Exception ignored) {}
                 listener.onMessage(data);
            }
        } catch (Exception e) {
            try {
                api.logging().logToError("SseTransport: Failed to parse SSE from POST response: " + e.getMessage());
            } catch (Exception ignored) {}
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
