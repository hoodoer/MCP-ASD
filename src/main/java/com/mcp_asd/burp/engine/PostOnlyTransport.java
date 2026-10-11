package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.ConnectionConfiguration;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * MCP transport that uses only HTTP POST (no GET). For servers that do not
 * support GET (e.g. no SSE stream). Each JSON-RPC message is sent as a POST;
 * the response is read from the HTTP response body.
 *
 * Requests go through Burp's HTTP API, so upstream proxy settings, session handling
 * rules, Burp's TLS handling and Burp's client TLS certificates (for mTLS) all apply,
 * and the traffic appears in Logger.
 */
public class PostOnlyTransport implements McpTransport {
    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final RequestOptions REQUEST_OPTIONS = RequestOptions.requestOptions()
            .withRedirectionMode(RedirectionMode.NEVER)
            .withResponseTimeout(60_000);

    private final MontoyaApi api;
    private final GlobalSettings settings;
    private ConnectionConfiguration config;
    private TransportListener listener;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "MCP-ASD-PostOnly");
        t.setDaemon(true);
        return t;
    });

    public PostOnlyTransport(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;
        this.listener = listener;
        api.logging().logToOutput("PostOnlyTransport: Connected (POST-only, no GET).");
        listener.onOpen();
    }

    @Override
    public void send(String message) {
        if (config == null) return;

        try {
            executor.submit(() -> {
                try {
                    HttpRequest request = buildRequest(message);
                    api.logging().logToOutput("PostOnlyTransport: POST to " + request.url() + ": " + message);

                    HttpRequestResponse requestResponse = api.http().sendRequest(request, REQUEST_OPTIONS);
                    if (!requestResponse.hasResponse()) {
                        throw new RuntimeException("No response from " + request.url() + " (connection failed or timed out)");
                    }

                    HttpResponse response = requestResponse.response();
                    String body = new String(response.body().getBytes(), StandardCharsets.UTF_8);
                    int code = response.statusCode();
                    if (code < 200 || code > 299) {
                        String reason = response.reasonPhrase();
                        api.logging().logToError("PostOnlyTransport: HTTP " + code + " " + reason + " body: " + body);
                        listener.onError(new RuntimeException("HTTP " + code + " " + reason + (body.isEmpty() ? "" : " " + body)));
                        return;
                    }
                    if (!body.trim().isEmpty()) {
                        listener.onMessage(body);
                    }
                } catch (Exception e) {
                    api.logging().logToError("PostOnlyTransport: Send failed: " + e.getMessage());
                    listener.onError(e);
                }
            });
        } catch (RejectedExecutionException e) {
            // Transport already closed
        }
    }

    private HttpRequest buildRequest(String message) {
        boolean secure = config.isUseTls() || config.isUseMtls();
        int port = config.getPort();
        HttpService service = HttpService.httpService(config.getHost(), port, secure);

        boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
        String hostHeader = defaultPort ? config.getHost() : config.getHost() + ":" + port;
        String path = config.getPath() == null || config.getPath().isEmpty() ? "/" : config.getPath();

        HttpRequest request = HttpRequest.httpRequest(service,
                "POST " + path + " HTTP/1.1\r\n" +
                "Host: " + hostHeader + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Accept: application/json\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n");

        for (var header : config.getHeaders().entrySet()) {
            request = request.withAddedHeader(header.getKey(), header.getValue());
        }

        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        return request
                .withBody(ByteArray.byteArray(body))
                .withHeader("Content-Length", String.valueOf(body.length));
    }

    @Override
    public void close() {
        executor.shutdownNow();
        if (listener != null) {
            listener.onClose();
        }
    }
}
