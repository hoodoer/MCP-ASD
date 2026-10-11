package com.mcp_asd.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.mcp_asd.burp.engine.EnumerationEngine;
import com.mcp_asd.burp.engine.SessionStore;
import org.json.JSONObject;

import burp.api.montoya.core.ToolType;
import org.json.JSONException;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class McpProxy implements burp.api.montoya.http.handler.HttpHandler {
    public static final String VIRTUAL_HOST = "mcp-asd.local";
    private static final String TOKEN_HEADER = "X-MCP-ASD-Token";
    private static final ToolType[] BRIDGED_TOOLS = {
            ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER, ToolType.EXTENSIONS
    };
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_BODY_BYTES = 10 * 1024 * 1024;
    private static final int READ_TIMEOUT_MS = 30_000;
    private static final int RESPONSE_TIMEOUT_SECONDS = 60;

    private final MontoyaApi api;
    private final SessionStore sessionStore;
    private final EnumerationEngine engine;
    private volatile int internalPort; // Ensure visibility across threads
    private final ExecutorService executorService;
    private ServerSocket serverSocket;
    private volatile boolean running = true;
    // Per-load secret the HttpHandler adds to bridged requests; the socket rejects anything without it
    private final String authToken;

    public McpProxy(MontoyaApi api, SessionStore sessionStore, EnumerationEngine engine) {
        this.api = api;
        this.sessionStore = sessionStore;
        this.engine = engine;
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        this.authToken = HexFormat.of().formatHex(secret);
        // Cached pool for Intruder bursts; daemon threads so nothing outlives an unload
        this.executorService = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "MCP-ASD-Proxy-Client");
            t.setDaemon(true);
            return t;
        });
        startInternalServer();
    }

    public int getInternalPort() {
        return internalPort;
    }

    /**
     * Stops the internal server. Closing the socket breaks the accept() loop,
     * and shutdownNow() interrupts any client handlers waiting on a response.
     */
    public void shutdown() {
        running = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {}
        }
        executorService.shutdownNow();
    }

    private void startInternalServer() {
        // Bind synchronously so the port is known before anything tries to use it
        try {
            // Increased backlog to 100 to handle Intruder bursts
            serverSocket = new ServerSocket(0, 100, InetAddress.getByName("127.0.0.1"));
            internalPort = serverSocket.getLocalPort();
            api.logging().logToOutput("Internal MCP Proxy Server (Raw Socket) started on port " + internalPort);
        } catch (IOException e) {
            api.logging().logToError("CRITICAL: Failed to start internal socket server: " + e.getMessage());
            return;
        }

        Thread acceptThread = new Thread(() -> {
            try {
                while (running) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        executorService.submit(() -> handleClient(clientSocket));
                    } catch (IOException e) {
                        if (!running) break; // Socket closed by shutdown()
                        api.logging().logToError("Error accepting connection: " + e.getMessage());
                    }
                }
            } catch (Throwable t) {
                if (running) api.logging().logToError(t);
            }
        }, "MCP-ASD-Proxy-Server");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void handleClient(Socket socket) {
        try (Socket client = socket;
             InputStream in = new BufferedInputStream(client.getInputStream());
             OutputStream out = client.getOutputStream()) {

            client.setSoTimeout(READ_TIMEOUT_MS); // Don't let idle connections pin a thread
            api.logging().logToOutput("InternalProxy: Connection accepted.");

            // --- Request line + headers ---
            List<String> lines = readHeaderLines(in);
            if (lines == null || lines.isEmpty()) {
                writeError(out, 400, "Bad Request", "Malformed or oversized request headers.");
                return;
            }

            String[] requestLine = lines.get(0).split(" ");
            if (requestLine.length < 2 || !"POST".equalsIgnoreCase(requestLine[0])) {
                writeError(out, 405, "Method Not Allowed", "Only POST is supported.");
                return;
            }

            String host = null;
            String token = null;
            long contentLength = -1;
            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i);
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim();
                switch (name) {
                    case "host" -> host = value;
                    case "x-mcp-asd-token" -> token = value;
                    case "content-length" -> {
                        try {
                            contentLength = Long.parseLong(value);
                        } catch (NumberFormatException e) {
                            writeError(out, 400, "Bad Request", "Invalid Content-Length.");
                            return;
                        }
                    }
                    default -> { }
                }
            }

            // Only requests that came through our HttpHandler carry the token and virtual host.
            // This rejects other local processes and browser-originated (CSRF / DNS-rebinding) requests.
            if (!isVirtualHost(host) || !isValidToken(token)) {
                api.logging().logToError("InternalProxy: Rejected unauthenticated request (Host: " + host + ").");
                writeError(out, 401, "Unauthorized",
                        "Requests must be sent from Burp (Repeater/Intruder/Scanner) with 'Host: " + VIRTUAL_HOST + "'.");
                return;
            }

            if (contentLength <= 0) {
                writeError(out, 411, "Length Required", "Content-Length is 0 or missing.");
                return;
            }
            if (contentLength > MAX_BODY_BYTES) {
                writeError(out, 413, "Payload Too Large", "Request body exceeds " + MAX_BODY_BYTES + " bytes.");
                return;
            }

            // --- Body (Content-Length is a byte count, so read bytes then decode) ---
            byte[] bodyBytes = in.readNBytes((int) contentLength);
            if (bodyBytes.length < contentLength) {
                writeError(out, 400, "Bad Request", "Request body shorter than Content-Length.");
                return;
            }
            String requestBody = new String(bodyBytes, StandardCharsets.UTF_8);
            api.logging().logToOutput("InternalProxy: Body read: " + requestBody);

            JSONObject jsonRequest;
            try {
                jsonRequest = new JSONObject(requestBody);
            } catch (JSONException e) {
                writeError(out, 400, "Bad Request", "Body is not a JSON object: " + e.getMessage());
                return;
            }

            // Auto-generate a new ID to ensure correlation works in Intruder
            // (Burp sends identical IDs by default, which causes collisions)
            String id = UUID.randomUUID().toString();
            jsonRequest.put("id", id);

            // 1. Create Future
            CompletableFuture<JSONObject> future = new CompletableFuture<>();
            sessionStore.registerRequest(id, future);
            api.logging().logToOutput("InternalProxy: Registered future for ID: " + id);

            // 2. Send Request via Engine
            engine.sendRequest(jsonRequest.toString());

            // 3. Wait for Response (Block)
            JSONObject jsonResponse;
            try {
                jsonResponse = future.get(RESPONSE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                sessionStore.removeRequest(id);
                writeError(out, 504, "Gateway Timeout", "No response from MCP server within " + RESPONSE_TIMEOUT_SECONDS + "s.");
                return;
            } catch (InterruptedException e) {
                sessionStore.removeRequest(id);
                Thread.currentThread().interrupt(); // Extension unloading
                return;
            }
            api.logging().logToOutput("InternalProxy: Response received: " + jsonResponse);

            // 4. Send HTTP Response
            writeResponse(out, 200, "OK", jsonResponse.toString());
            api.logging().logToOutput("InternalProxy: Response written to socket.");

        } catch (Exception e) {
            // Headers may already be partially written, so just log; the socket is closed by try-with-resources
            if (running) api.logging().logToError("InternalProxy Error: " + e.getMessage(), e);
        }
    }

    /**
     * Reads the request line and headers as ISO-8859-1 lines up to the blank line.
     * Returns null if the stream ends early or the header block exceeds MAX_HEADER_BYTES.
     */
    private static List<String> readHeaderLines(InputStream in) throws IOException {
        List<String> lines = new ArrayList<>();
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int total = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (++total > MAX_HEADER_BYTES) return null;
            if (b == '\n') {
                String s = line.toString(StandardCharsets.ISO_8859_1);
                if (s.endsWith("\r")) s = s.substring(0, s.length() - 1);
                if (s.isEmpty()) return lines;
                lines.add(s);
                line.reset();
            } else {
                line.write(b);
            }
        }
        return null;
    }

    private static boolean isVirtualHost(String hostHeader) {
        if (hostHeader == null) return false;
        String host = hostHeader.toLowerCase(Locale.ROOT);
        int colon = host.indexOf(':');
        if (colon >= 0) host = host.substring(0, colon);
        return VIRTUAL_HOST.equals(host);
    }

    private boolean isValidToken(String token) {
        return token != null && MessageDigest.isEqual(
                token.getBytes(StandardCharsets.UTF_8), authToken.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeError(OutputStream out, int code, String reason, String message) throws IOException {
        writeResponse(out, code, reason, new JSONObject().put("error", message).toString());
    }

    private static void writeResponse(OutputStream out, int code, String reason, String jsonBody) throws IOException {
        byte[] body = jsonBody.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + code + " " + reason + "\r\n" +
                "Content-Type: application/json\r\n" +
                "Connection: close\r\n" +
                "Content-Length: " + body.length + "\r\n" +
                "\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Intercept if it's our virtual endpoint: either the virtual Host header, or aimed straight at the
        // bridge's port (Intruder rewrites Host to match its target, i.e. 127.0.0.1:<port>)
        HttpService service = requestToBeSent.httpService();
        boolean aimedAtBridge = internalPort > 0 && service.port() == internalPort
                && ("127.0.0.1".equals(service.host()) || "localhost".equalsIgnoreCase(service.host()));
        boolean isTarget = requestToBeSent.path().startsWith("/invoke")
                && (aimedAtBridge || isVirtualHost(requestToBeSent.headerValue("Host")));

        // Only bridge Burp's own testing tools. Proxy traffic is excluded so a web page in the
        // proxied browser can't reach the bridge by requesting http://mcp-asd.local/invoke.
        if (isTarget && requestToBeSent.toolSource().isFromTool(BRIDGED_TOOLS)) {
            // Redirect traffic to our internal server
            if (internalPort > 0) {
                HttpService internalService = HttpService.httpService("127.0.0.1", internalPort, false);
                return RequestToBeSentAction.continueWith(requestToBeSent
                        .withService(internalService)
                        .withHeader("Host", VIRTUAL_HOST) // Normalise, so the listener's Host check passes
                        .withHeader(TOKEN_HEADER, authToken));
            } else {
                 api.logging().logToError("Internal server not ready yet.");
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
