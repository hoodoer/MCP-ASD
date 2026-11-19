package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * MCP Streamable HTTP transport (spec 2026-07-28, with 2025-era back-compat).
 */
public class StreamableHttpTransport implements McpTransport {
    private static final String USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    private final MontoyaApi api;
    private final GlobalSettings settings;
    private OkHttpClient client;
    private ConnectionConfiguration config;
    private TransportListener listener;
    private boolean forceHttp1 = false;

    private volatile String postUrl;
    private volatile String sessionId;         // Mcp-Session-Id, legacy only
    private volatile String protocolVersion;   // accepted version, set by the engine 
    private volatile String advertisedVersion; // pre-handshake seed for the first probe; may be reseeded for a legacy fallback
    private volatile boolean versionSet;       // engine has reported the accepted version
    private volatile boolean closed;

    // Serialization: FIFO queue + single in-flight slot, guarded by `lock`.
    private final Object lock = new Object();
    private final ArrayDeque<QueuedRequest> queue = new ArrayDeque<>();
    private boolean inFlight;

    private static final class QueuedRequest {
        final String message;
        final String id; // JSON-RPC id (null for notifications)
        final String method; // JSON-RPC method (null if unparseable) — Mcp-Method
        final String name; // params.name / params.uri (null if not applicable) — Mcp-Name
        QueuedRequest(String message, String id, String method, String name) {
            this.message = message;
            this.id = id;
            this.method = method;
            this.name = name;
        }
    }

    public StreamableHttpTransport(MontoyaApi api, GlobalSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    public void setForceHttp1(boolean forceHttp1) {
        this.forceHttp1 = forceHttp1;
    }

    /**
     * Pre-handshake version seed: carried by the first probe (server/discover)
     * until the server answers; the engine may reseed it (e.g. to a legacy
     * revision) before falling back to the classic initialize handshake.
     */
    public void setAdvertisedVersion(String version) {
        this.advertisedVersion = version;
    }

    @Override
    public void setProtocolVersion(String version) {
        this.protocolVersion = version;
        this.versionSet = true;
        api.logging().logToOutput("StreamableHttpTransport: Protocol version set to "
                + (version == null ? "none (legacy)" : version));
    }

    @Override
    public void connect(ConnectionConfiguration config, TransportListener listener) {
        this.config = config;
        this.listener = listener;
        this.closed = false;
        this.sessionId = null;
        this.protocolVersion = null;
        this.versionSet = false;

        okhttp3.Dispatcher dispatcher = new okhttp3.Dispatcher();
        dispatcher.setMaxRequestsPerHost(1); // belt-and-suspenders; the queue is the real guarantee

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS) // bounds a hung request-scoped stream
                .dispatcher(dispatcher);

        if (forceHttp1) {
            builder.protocols(Arrays.asList(Protocol.HTTP_1_1));
            api.logging().logToOutput("StreamableHttpTransport: Forcing HTTP/1.1");
        }

        TlsSupport.configure(builder, api, settings, config, "StreamableHttpTransport");
        client = builder.build();

        boolean secure = config.isUseTls() || config.isUseMtls();
        postUrl = (secure ? "https://" : "http://") + config.getHost() + ":" + config.getPort() + config.getPath();
        api.logging().logToOutput("StreamableHttpTransport: Connected (single POST endpoint: " + postUrl + ")");

        // No persistent stream: signal readiness so the engine can send its handshake probe.
        listener.onOpen();
    }

    @Override
    public void send(String message) {
        if (client == null || config == null || closed) return;

        String id = parseId(message);
        String method = parseMethod(message);
        String name = parseName(message);
        boolean start;
        QueuedRequest req = new QueuedRequest(message, id, method, name);
        synchronized (lock) {
            if (closed) return;
            if (!inFlight) {
                inFlight = true;
                start = true;
            } else {
                queue.add(req);
                start = false;
            }
        }
        if (start) {
            startPost(req);
        } else {
            api.logging().logToOutput("StreamableHttpTransport: Queued request (queue size " + queue.size() + ")");
        }
    }

    private String parseId(String message) {
        try {
            JSONObject json = new JSONObject(message);
            if (json.has("id") && !json.isNull("id")) {
                return String.valueOf(json.get("id"));
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** JSON-RPC method of the message (null if unparseable) — for the modern-era {@code Mcp-Method} header. */
    private String parseMethod(String message) {
        try {
            JSONObject json = new JSONObject(message);
            if (json.has("method") && !json.isNull("method")) {
                return json.getString("method");
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** params.name / params.uri for named-target methods — for the modern-era {@code Mcp-Name} header. */
    private String parseName(String message) {
        try {
            JSONObject json = new JSONObject(message);
            String method = json.optString("method", null);
            if (("tools/call".equals(method) || "resources/read".equals(method) || "prompts/get".equals(method))
                    && json.has("params") && json.get("params") instanceof JSONObject params) {
                if (params.has("name") && !params.isNull("name")) return params.getString("name");
                if (params.has("uri") && !params.isNull("uri")) return params.getString("uri");
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void startPost(QueuedRequest req) {
        String body = req.message;
        String versionInForce = effectiveVersion();
        if (modernRegime() && versionInForce != null) {
            body = injectProtocolMeta(body, versionInForce);
        }

        Request.Builder rb = new Request.Builder()
                .url(postUrl)
                .post(RequestBody.create(body, MediaType.get("application/json")))
                .addHeader("User-Agent", USER_AGENT)
                .addHeader("Accept", "application/json, text/event-stream")
                .addHeader("Cache-Control", "no-cache");

        if (!modernRegime() && sessionId != null && !sessionId.isEmpty()) {
            rb.addHeader("Mcp-Session-Id", sessionId);
        }
        String version = protocolVersionHeader();
        if (version != null && !version.isEmpty()) {
            rb.addHeader("MCP-Protocol-Version", version);
        }
        if (modernRegime()) {
            if (req.method != null) {
                rb.addHeader("Mcp-Method", encodeHeaderValue(req.method));
            }
            if (req.name != null) {
                rb.addHeader("Mcp-Name", encodeHeaderValue(req.name));
            }
        }
        if (config != null) {
            config.getHeaders().forEach(rb::addHeader);
        }

        Request request = rb.build();
        api.logging().logToOutput("StreamableHttpTransport: POST to " + postUrl + " (id=" + req.id + "): " + body);

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                if (call.isCanceled() || closed) return;
                api.logging().logToError("StreamableHttpTransport: Send failed (id=" + req.id + "): " + e.getMessage());
                deliverSyntheticError(req, e.getMessage());
                finishInFlight();
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull okhttp3.Response response) {
                handleResponse(req, call, response);
            }
        });
    }

    private void handleResponse(QueuedRequest req, Call call, okhttp3.Response response) {
        // Capture the session id (legacy-era servers issue it, typically on the initialize
        // response). 2026+ servers use no protocol-level sessions.
        String sid = response.header("Mcp-Session-Id");
        if (sid != null && !sid.isEmpty() && !modernRegime()) {
            sessionId = sid;
            api.logging().logToOutput("StreamableHttpTransport: Captured Mcp-Session-Id");
        }

        int code = response.code();
        try (response) {
            if (code == 202) {
                api.logging().logToOutput("StreamableHttpTransport: 202 Accepted (id=" + req.id + ")");
                finishInFlight();
                return;
            }

            if (response.body() == null) {
                finishInFlight();
                return;
            }

            if (response.isSuccessful()) {
                okhttp3.MediaType ct = response.body().contentType();
                boolean isSse = ct != null && "text".equalsIgnoreCase(ct.type()) && "event-stream".equalsIgnoreCase(ct.subtype());
                if (isSse) {
                    handleRequestScopedSse(req, call, response.body().charStream());
                } else {
                    String body = response.body().string();
                    if (body != null && !body.trim().isEmpty()) {
                        api.logging().logToOutput("StreamableHttpTransport: JSON response (id=" + req.id + "): " + body);
                        listener.onMessage(body);
                    } else if (req.id != null) {
                        // A request answered with an empty 2xx body has no JSON-RPC response — surface it
                        // so the correlated bridge future does not wait out the full timeout.
                        deliverSyntheticError(req, "Empty response body (HTTP " + code + ")");
                    }
                    finishInFlight();
                }
            } else {
                String body = "";
                try {
                    body = response.body().string();
                } catch (Exception ignored) {}
                api.logging().logToError("StreamableHttpTransport: HTTP " + code + " (id=" + req.id + "): " + snippet(body));
                if (!deliverServerError(req, body)) {
                    deliverSyntheticError(req, "HTTP " + code + " " + response.message() + (body.isEmpty() ? "" : ": " + snippet(body)));
                }
                finishInFlight();
            }
        } catch (Exception e) {
            api.logging().logToError("StreamableHttpTransport: Failed to handle response (id=" + req.id + "): " + e.getMessage());
            deliverSyntheticError(req, e.getMessage());
            finishInFlight();
        }
    }

    private void handleRequestScopedSse(QueuedRequest req, Call call, java.io.Reader reader) {
        api.logging().logToOutput("StreamableHttpTransport: Request-scoped SSE stream (id=" + req.id + ")");
        try (BufferedReader br = new BufferedReader(reader)) {
            String line;
            StringBuilder dataBuffer = new StringBuilder();
            boolean done = false;
            while (!done && (line = br.readLine()) != null) {
                if (line.startsWith("data:")) {
                    dataBuffer.append(line.substring(5).trim());
                } else if (line.isEmpty()) {
                    if (dataBuffer.length() > 0) {
                        String data = dataBuffer.toString();
                        dataBuffer.setLength(0);
                        api.logging().logToOutput("StreamableHttpTransport: SSE event (id=" + req.id + "): " + data);
                        listener.onMessage(data);
                        if (isFinalResponseFor(req, data)) {
                            // Final JSON-RPC response delivered — cancel the stream (closes it) so a
                            // never-closing server cannot hold the in-flight slot.
                            call.cancel();
                            done = true;
                        }
                    }
                }
            }
            // EOF with data pending
            if (!done && dataBuffer.length() > 0) {
                String data = dataBuffer.toString();
                api.logging().logToOutput("StreamableHttpTransport: SSE event (EOF, id=" + req.id + "): " + data);
                listener.onMessage(data);
            }
        } catch (Exception e) {
            if (!call.isCanceled() && !closed) {
                api.logging().logToError("StreamableHttpTransport: SSE stream read failed (id=" + req.id + "): " + e.getMessage());
                deliverSyntheticError(req, e.getMessage());
            }
        } finally {
            finishInFlight();
        }
    }

    /** True if `event` is the final JSON-RPC response for the in-flight request (has its id + result/error). */
    private boolean isFinalResponseFor(QueuedRequest req, String event) {
        if (req.id == null) return false;
        try {
            JSONObject json = new JSONObject(event);
            if (json.has("id") && !json.isNull("id")
                    && req.id.equals(String.valueOf(json.get("id")))
                    && (json.has("result") || json.has("error"))) {
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * The version in force for the next request: the engine-reported accepted
     * version once known, otherwise the pre-handshake advertised seed.
     */
    private String effectiveVersion() {
        return versionSet ? protocolVersion : advertisedVersion;
    }

    /** Modern era (≥ 2026-07-28) regime: the version in force is a modern revision. */
    private boolean modernRegime() {
        String v = effectiveVersion();
        return v != null && v.compareTo("2026-07-28") >= 0;
    }

    /**
     * The {@code MCP-Protocol-Version} header value for the next request
     * (null = omit the header), per the version-in-force regime:
     * <ul>
     * <li>modern (≥ 2026-07-28): the version, on every request (MUST);</li>
     * <li>legacy ≥ 2025-06-18: the version, on every request (MUST);</li>
     * <li>legacy 2025-03-26 / 2024-11-05 / unknown: never (header not defined).</li>
     * </ul>
     */
    private String protocolVersionHeader() {
        String v = effectiveVersion();
        if (v == null) return null;
        if (v.compareTo("2026-07-28") >= 0) return v;
        return v.compareTo("2025-06-18") >= 0 ? v : null;
    }

    /**
     * 2026-07-28 requires every request to declare the protocol version,
     * client capabilities, and client identity in {@code _meta}
     * ({@code io.modelcontextprotocol/protocolVersion} must match the
     * {@code MCP-Protocol-Version} header). Injected into {@code params._meta},
     * creating {@code params} when the message has none; top-level {@code _meta}
     * is only used when {@code params} exists but is not an object.
     */
    private String injectProtocolMeta(String message, String version) {
        try {
            JSONObject json = new JSONObject(message);
            JSONObject target;
            if (json.has("params") && json.get("params") instanceof JSONObject params) {
                target = params;
            } else if (json.has("params")) {
                target = json; // params is not an object: no room for _meta inside
            } else {
                target = new JSONObject();
                json.put("params", target);
            }
            JSONObject meta;
            if (target.has("_meta") && target.get("_meta") instanceof JSONObject existing) {
                meta = existing;
            } else {
                meta = new JSONObject();
                target.put("_meta", meta);
            }
            meta.put("io.modelcontextprotocol/protocolVersion", version);
            meta.put("io.modelcontextprotocol/clientCapabilities", new JSONObject());
            meta.put("io.modelcontextprotocol/clientInfo",
                    new JSONObject().put("name", "MCP-ASD").put("version", "1.3.0"));
            return json.toString();
        } catch (Exception e) {
            api.logging().logToError("StreamableHttpTransport: _meta injection failed: " + e.getMessage());
            return message;
        }
    }

    /**
     * Structured-error pass-through: when a non-2xx body parses as a JSON-RPC
     * error object, deliver it verbatim (id normalized to the in-flight
     * request's id so correlation still works) so the engine can inspect
     * {@code error.code} / {@code error.data}. Returns false when the body is
     * not a JSON-RPC error (caller falls back to the synthetic error).
     */
    private boolean deliverServerError(QueuedRequest req, String body) {
        if (req.id == null || body == null || body.trim().isEmpty()) return false;
        try {
            JSONObject json = new JSONObject(body);
            if (json.has("error") && json.get("error") instanceof JSONObject) {
                json.put("id", req.id);
                if (!json.has("jsonrpc")) json.put("jsonrpc", "2.0");
                api.logging().logToOutput("StreamableHttpTransport: Server error (id=" + req.id + "): " + json.toString());
                listener.onMessage(json.toString());
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * 2026-07-28 request-metadata encoding: a header value is sent as
     * {@code =?base64?<base64>?=} when it is not plain printable ASCII, has
     * leading/trailing whitespace, or already looks like a sentinel.
     */
    private static String encodeHeaderValue(String value) {
        if (value == null) return null;
        boolean needs = value.isEmpty() || value.codePoints().anyMatch(c -> c < 0x20 || c > 0x7e);
        if (!needs) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if (first == ' ' || last == ' ') needs = true;
        }
        if (!needs && value.startsWith("=?base64?") && value.endsWith("?=")) needs = true;
        if (!needs) return value;
        return "=?base64?" + java.util.Base64.getEncoder()
                .encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "?=";
    }

    /** Deliver a synthesized JSON-RPC error so a failed POST still correlates (no 60s hang). */
    private void deliverSyntheticError(QueuedRequest req, String message) {
        if (req.id == null) return; // notifications have nothing to correlate against
        try {
            JSONObject error = new JSONObject();
            error.put("jsonrpc", "2.0");
            error.put("id", req.id);
            JSONObject err = new JSONObject();
            err.put("code", -32000);
            err.put("message", message == null ? "Transport error" : message);
            error.put("error", err);
            String synthetic = error.toString();
            api.logging().logToOutput("StreamableHttpTransport: Synthetic error (id=" + req.id + "): " + synthetic);
            listener.onMessage(synthetic);
        } catch (Exception ignored) {}
    }

    private void finishInFlight() {
        QueuedRequest next = null;
        synchronized (lock) {
            inFlight = false;
            if (!closed && !queue.isEmpty()) {
                next = queue.poll();
                inFlight = true;
            }
        }
        if (next != null) {
            startPost(next);
        }
    }

    /** Collapse whitespace and cap length so an error body never floods the log/status. */
    private static String snippet(String body) {
        if (body == null) return "";
        String s = body.strip().replaceAll("\\s+", " ");
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }

    @Override
    public void close() {
        closed = true;
        synchronized (lock) {
            queue.clear();
        }
        if (client != null) {
            client.dispatcher().cancelAll();
            client.dispatcher().executorService().shutdownNow();
            client.connectionPool().evictAll();
        }
        if (listener != null) {
            listener.onClose();
        }
    }
}
