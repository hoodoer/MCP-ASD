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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class McpProxy implements burp.api.montoya.http.handler.HttpHandler {
    private final MontoyaApi api;
    private final SessionStore sessionStore;
    private final EnumerationEngine engine;
    private volatile int internalPort; // Ensure visibility across threads
    private final ExecutorService executorService;

    public McpProxy(MontoyaApi api, SessionStore sessionStore, EnumerationEngine engine) {
        this.api = api;
        this.sessionStore = sessionStore;
        this.engine = engine;
        this.executorService = Executors.newCachedThreadPool(); // Use cached pool for Intruder bursts
        startInternalServer();
    }

    public int getInternalPort() {
        return internalPort;
    }

    private void startInternalServer() {
        new Thread(() -> {
            // Increased backlog to 100 to handle Intruder bursts
            try (ServerSocket serverSocket = new ServerSocket(0, 100, InetAddress.getByName("127.0.0.1"))) {
                internalPort = serverSocket.getLocalPort();
                api.logging().logToOutput("Internal MCP Proxy Server (Raw Socket) started on port " + internalPort);

                while (true) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        // clientSocket.setSoTimeout(30000); // Optional: Read timeout
                        executorService.submit(() -> handleClient(clientSocket));
                    } catch (IOException e) {
                        api.logging().logToError("Error accepting connection: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                api.logging().logToError("CRITICAL: Failed to start internal socket server: " + e.getMessage());
            }
        }).start();

        // Give the server a moment to bind and set the port
        try { Thread.sleep(200); } catch (InterruptedException ignored) {}
    }

    private void handleClient(Socket socket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             OutputStream out = socket.getOutputStream()) {

            api.logging().logToOutput("InternalProxy: Connection accepted.");

            // Read Request Headers
            String line;
            int contentLength = 0;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                // api.logging().logToOutput("InternalProxy Header: " + line); 
                if (line.toLowerCase().startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                }
            }
            api.logging().logToOutput("InternalProxy: Headers read. Content-Length: " + contentLength);

            // Read Body
            if (contentLength > 0) {
                char[] bodyChars = new char[contentLength];
                int read = 0;
                while (read < contentLength) {
                    int count = in.read(bodyChars, read, contentLength - read);
                    if (count == -1) break;
                    read += count;
                }
                
                String requestBody = new String(bodyChars);
                api.logging().logToOutput("InternalProxy: Body read: " + requestBody);

                            // Process Logic
                            JSONObject jsonRequest = new JSONObject(requestBody);
                            
                            // Auto-generate a new ID to ensure correlation works in Intruder
                            // (Burp sends identical IDs by default, which causes collisions)
                            String id = java.util.UUID.randomUUID().toString();
                            jsonRequest.put("id", id);
                            String newRequestBody = jsonRequest.toString();
                
                            // 1. Create Future
                            CompletableFuture<JSONObject> future = new CompletableFuture<>();
                            sessionStore.registerRequest(id, future);
                            api.logging().logToOutput("InternalProxy: Registered future for ID: " + id);
                
                            // 2. Send Request via Engine
                            engine.sendRequest(newRequestBody);
                
                            // 3. Wait for Response (Block)                api.logging().logToOutput("InternalProxy: Waiting for response...");
                JSONObject jsonResponse = future.get(60, TimeUnit.SECONDS);
                api.logging().logToOutput("InternalProxy: Response received: " + jsonResponse.toString());
                
                String responseString = jsonResponse.toString();

                // 4. Send HTTP Response
                String httpResponse = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Connection: close\r\n" +
                        "Content-Length: " + responseString.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                        "\r\n" +
                        responseString;

                out.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                out.flush();
                api.logging().logToOutput("InternalProxy: Response written to socket.");
            } else {
                api.logging().logToError("InternalProxy: Error - Content-Length is 0 or missing.");
            }

        } catch (Exception e) {
            api.logging().logToError("InternalProxy Error: " + e.getMessage());
            e.printStackTrace();
            String errorJson = "{\"error\": \"" + e.getMessage() + "\"}";
            String errorResponse = "HTTP/1.1 500 Internal Server Error\r\n" +
                    "Content-Type: application/json\r\n" +
                    "Content-Length: " + errorJson.length() + "\r\n" +
                    "\r\n" +
                    errorJson;
            try {
                if (!socket.isClosed()) {
                    socket.getOutputStream().write(errorResponse.getBytes(StandardCharsets.UTF_8));
                }
            } catch (IOException ignored) {}
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Intercept if it's our virtual endpoint (checking Host header or URL path)
        boolean isTarget = false;
        if (requestToBeSent.url().contains("/invoke")) {
             if (requestToBeSent.hasHeader("Host", "mcp-asd.local") || requestToBeSent.url().contains("mcp-asd.local")) {
                 isTarget = true;
             }
        }

        if (isTarget) {
            // Redirect traffic to our internal server
            if (internalPort > 0) {
                // Debug log to verify Intruder hits this
                // api.logging().logToOutput("Redirecting request (" + requestToBeSent.toolSource().toolType() + ") to 127.0.0.1:" + internalPort);
                HttpService internalService = HttpService.httpService("127.0.0.1", internalPort, false);
                return RequestToBeSentAction.continueWith(requestToBeSent.withService(internalService));
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
