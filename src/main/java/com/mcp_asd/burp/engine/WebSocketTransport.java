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
import com.mcp_asd.burp.GlobalSettings;

public class WebSocketTransport implements McpTransport {
    private final MontoyaApi api;
    private final GlobalSettings settings;
    private OkHttpClient client;
    private WebSocket webSocket;
    private ConnectionConfiguration config;

    public WebSocketTransport(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.SECONDS);

        TlsSupport.configure(builder, api, settings, config, "WebSocketTransport");

        client = builder.build();

        String url = "http://" + config.getHost() + ":" + config.getPort() + config.getPath();
        if (config.isUseTls() || config.isUseMtls()) {
            url = url.replace("http://", "https://");
        }
        // OkHttp handles ws:// vs http:// automatically in some contexts, 
        // but for WebSockets we should ensure it's ws:// or wss://
        url = url.replace("http://", "ws://").replace("https://", "wss://");

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        
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
                    String body = "";
                    try {
                        body = response.body() != null ? response.body().string() : "";
                    } catch (Exception e) {
                        body = " (failed to read body)";
                    }
                    listener.onError(new RuntimeException("HTTP " + response.code() + ": " + response.message() + "\nBody: " + body));
                } else {
                    listener.onError(t);
                }
            }
        });
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
