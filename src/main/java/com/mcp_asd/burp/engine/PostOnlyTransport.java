package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * MCP transport that uses only HTTP POST (no GET). For servers that do not
 * support GET (e.g. no SSE stream). Each JSON-RPC message is sent as a POST;
 * the response is read from the HTTP response body.
 */
public class PostOnlyTransport implements McpTransport {
    private final MontoyaApi api;
    private final GlobalSettings settings;
    private OkHttpClient client;
    private ConnectionConfiguration config;
    private TransportListener listener;
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public PostOnlyTransport(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;
        this.listener = listener;

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS);

        try {
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            api.logging().logToError("PostOnlyTransport: Failed to create SSL context: " + e.getMessage());
        }

        if (config.isUseMtls()) {
            configureMtls(builder, config);
        }

        if (settings != null && settings.isProxyTrafficEnabled()) {
            String host = settings.getProxyHost();
            int port = settings.getProxyPort();
            if (host != null && !host.isEmpty() && port > 0) {
                api.logging().logToOutput("PostOnlyTransport: Using proxy " + host + ":" + port);
                builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port)));
            }
        }

        client = builder.build();
        api.logging().logToOutput("PostOnlyTransport: Connected (POST-only, no GET).");
        listener.onOpen();
    }

    @Override
    public void send(String message) {
        if (client == null || config == null) return;

        executor.submit(() -> {
            try {
                String url = "http://" + config.getHost() + ":" + config.getPort() + config.getPath();
                if (config.isUseTls() || config.isUseMtls()) {
                    url = url.replace("http://", "https://");
                }

                api.logging().logToOutput("PostOnlyTransport: POST to " + url + ": " + message);

                Request.Builder requestBuilder = new Request.Builder()
                        .url(url)
                        .post(RequestBody.create(message, MediaType.get("application/json")))
                        .addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                        .addHeader("Accept", "application/json")
                        .addHeader("Content-Type", "application/json");

                config.getHeaders().forEach(requestBuilder::addHeader);

                try (Response response = client.newCall(requestBuilder.build()).execute()) {
                    if (!response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";
                        api.logging().logToError("PostOnlyTransport: HTTP " + response.code() + " " + response.message() + " body: " + body);
                        listener.onError(new RuntimeException("HTTP " + response.code() + " " + response.message() + (body.isEmpty() ? "" : " " + body)));
                        return;
                    }
                    String responseBody = response.body() != null ? response.body().string() : "";
                    if (!responseBody.trim().isEmpty()) {
                        listener.onMessage(responseBody);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("PostOnlyTransport: Send failed: " + e.getMessage());
                listener.onError(e);
            }
        });
    }

    @Override
    public void close() {
        executor.shutdownNow();
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
        } catch (Exception e) {
            api.logging().logToError("PostOnlyTransport: Failed to configure mTLS: " + e.getMessage());
        }
    }
}
