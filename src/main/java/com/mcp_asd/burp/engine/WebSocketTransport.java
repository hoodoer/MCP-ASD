package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.concurrent.TimeUnit;

import com.mcp_asd.burp.ui.ConnectionConfiguration;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class WebSocketTransport implements McpTransport {
    private final MontoyaApi api;
    private OkHttpClient client;
    private WebSocket webSocket;
    private ConnectionConfiguration config;

    public WebSocketTransport(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.SECONDS);

        if (config.isUseMtls()) {
            configureMtls(builder, config);
        }

        client = builder.build();

        String url = "http://" + config.getHost() + ":" + config.getPort() + config.getPath();
        if (config.isUseMtls()) {
            url = url.replace("http://", "https://");
        }
        // OkHttp handles ws:// vs http:// automatically in some contexts, 
        // but for WebSockets we should ensure it's ws:// or wss://
        url = url.replace("http://", "ws://").replace("https://", "wss://");

        Request.Builder requestBuilder = new Request.Builder().url(url);
        
        // Add custom headers
        config.getHeaders().forEach(requestBuilder::addHeader);

        webSocket = client.newWebSocket(requestBuilder.build(), new WebSocketListener() {
            @Override
            public void onOpen(@NotNull WebSocket webSocket, @NotNull Response response) {
                listener.onOpen();
            }

            @Override
            public void onMessage(@NotNull WebSocket webSocket, @NotNull String text) {
                listener.onMessage(text);
            }

            @Override
            public void onClosing(@NotNull WebSocket webSocket, int code, @NotNull String reason) {
                webSocket.close(1000, null);
                listener.onClose();
            }

            @Override
            public void onFailure(@NotNull WebSocket webSocket, @NotNull Throwable t, @Nullable Response response) {
                if (response != null) {
                    listener.onError(new RuntimeException("HTTP " + response.code() + ": " + response.message()));
                } else {
                    listener.onError(t);
                }
            }
        });
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
            api.logging().logToError("Failed to configure mTLS for WebSocket: " + e.getMessage());
        }
    }

    @Override
    public void send(String message) {
        if (webSocket != null) {
            api.logging().logToOutput("WebSocketTransport: Sending: " + message);
            webSocket.send(message);
        } else {
            api.logging().logToError("WebSocketTransport: Cannot send, socket is null.");
        }
    }

    @Override
    public void close() {
        if (webSocket != null) {
            webSocket.close(1000, "Closing");
        }
        if (client != null) {
            client.dispatcher().executorService().shutdown();
        }
    }
}
