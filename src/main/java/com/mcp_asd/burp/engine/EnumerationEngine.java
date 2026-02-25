package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.DashboardTab;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.swing.SwingUtilities;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class EnumerationEngine implements TransportListener {
    private final MontoyaApi api;
    private final GlobalSettings settings;
    private DashboardTab dashboardTab;
    private final SessionStore sessionStore;
    private McpTransport transport;
    private CountDownLatch latch;
    private volatile boolean connectionFailed = false;
    private ConnectionConfiguration currentConfig;
    private volatile boolean cancelled = false;
    
    // Request IDs for tracking enumeration responses
    private String initializeRequestId;
    private String toolsRequestId;
    private String resourcesRequestId;
    private String promptsRequestId;
    
    private boolean toolsDone = false;
    private boolean resourcesDone = false;
    private boolean promptsDone = false;

    public EnumerationEngine(MontoyaApi api, DashboardTab dashboardTab, SessionStore sessionStore, GlobalSettings settings) {
        this.api = api;
        this.dashboardTab = dashboardTab;
        this.sessionStore = sessionStore;
        this.settings = settings;
    }

    public void setDashboardTab(DashboardTab dashboardTab) {
        this.dashboardTab = dashboardTab;
    }

    public void cancel() {
        this.cancelled = true;
        api.logging().logToOutput("Cancellation requested by user.");
        if (transport != null) {
            transport.close();
        }
        if (latch != null) {
            latch.countDown();
        }
        if (dashboardTab != null) {
            dashboardTab.setStatus("⚪ Cancelled", java.awt.Color.GRAY);
            dashboardTab.setCancelEnabled(false);
        }
    }

    public void start(ConnectionConfiguration config) {
        this.currentConfig = config;
        
        // Reset state
        this.cancelled = false;
        this.connectionFailed = false;
        this.toolsDone = false;
        this.resourcesDone = false;
        this.promptsDone = false;

        if (dashboardTab != null) {
            dashboardTab.setTarget(config.getHost(), config.getPort());
            dashboardTab.setStatus("🟠 Connecting via " + config.getTransport() + "...", java.awt.Color.ORANGE.darker());
            dashboardTab.setCancelEnabled(true);
        }
        
        new Thread(() -> {
            boolean success = attemptConnection(config, false);
            if (cancelled) return; // Exit if cancelled

            if (!success && !config.getTransport().equals("WebSocket") && !config.getTransport().equals("HTTP (POST only)")) {
                api.logging().logToOutput("Enumeration failed or timed out. Retrying with forced HTTP/1.1...");
                if (dashboardTab != null) {
                    dashboardTab.setStatus("🟠 Retrying (HTTP/1.1)...", java.awt.Color.ORANGE.darker());
                }
                attemptConnection(config, true);
            }
            
            if (dashboardTab != null) {
                dashboardTab.setCancelEnabled(false);
            }
        }).start();
    }

    private boolean attemptConnection(ConnectionConfiguration config, boolean forceHttp1) {
        if (cancelled) return false;
        try {
            latch = new CountDownLatch(1); // Wait for Handshake (initialize response)
            this.connectionFailed = false;

            if ("WebSocket".equals(config.getTransport())) {
                transport = new WebSocketTransport(api, settings);
            } else if ("HTTP (POST only)".equals(config.getTransport())) {
                transport = new PostOnlyTransport(api, settings);
            } else {
                SseTransport sse = new SseTransport(api, settings);
                if (forceHttp1) sse.setForceHttp1(true);
                transport = sse;
            }
            
            api.logging().logToOutput("Starting connection attempt (Force HTTP/1.1: " + forceHttp1 + ")");
            transport.connect(config, this);

            // Wait for INITIALIZE response, not full enumeration
            if (!latch.await(30, TimeUnit.SECONDS)) {
                api.logging().logToError("Connection attempt timed out waiting for handshake.");
                transport.close();
                return false;
            }
            
            if (cancelled) {
                api.logging().logToOutput("Connection attempt aborted (cancelled).");
                return false;
            }
            
            if (connectionFailed) {
                transport.close();
                return false;
            }
            
            api.logging().logToOutput("Handshake successful. Connection secured.");
            // Status remains "Enumerating..." set by onMessage
            return true;

        } catch (Exception e) {
            api.logging().logToError("Exception during connection attempt: " + e.getMessage());
            if (dashboardTab != null) {
                dashboardTab.setStatus("🔴 Connection Error: " + e.getMessage(), java.awt.Color.RED);
            }
            return false;
        }
    }

    public void sendRequest(String requestBody) {
        if (transport != null) {
            transport.send(requestBody);
        }
    }

    // --- TransportListener Implementation ---

    @Override
    public void onOpen() {
        api.logging().logToOutput("Transport connected.");
        if (dashboardTab != null) dashboardTab.setStatus("🔵 Handshaking...", java.awt.Color.BLUE.darker());
        
        // Trigger initial discovery
        JSONObject initParams = new JSONObject();
        initParams.put("protocolVersion", "2024-11-05");
        initParams.put("capabilities", new JSONObject());
        initParams.put("clientInfo", new JSONObject().put("name", "MCP-ASD").put("version", "1.0.1"));
        
        if (currentConfig != null && currentConfig.getInitializationOptions() != null && !currentConfig.getInitializationOptions().trim().isEmpty()) {
            try {
                JSONObject userParams = new JSONObject(currentConfig.getInitializationOptions());
                for (String key : userParams.keySet()) {
                    initParams.put(key, userParams.get(key));
                }
            } catch (Exception e) {
                api.logging().logToError("Invalid JSON in Initialization Options: " + e.getMessage());
            }
        }
        
        initializeRequestId = java.util.UUID.randomUUID().toString();
        
        JSONObject initRequest = new JSONObject();
        initRequest.put("jsonrpc", "2.0");
        initRequest.put("method", "initialize");
        initRequest.put("params", initParams);
        initRequest.put("id", initializeRequestId);

        sendRequest(initRequest.toString());
    }

    @Override
    public void onMessage(String data) {
        if (data == null || data.trim().isEmpty()) return;
        
        api.logging().logToOutput("Received event data: " + data);
        try {
            JSONObject json = null;
            if (data.trim().startsWith("[")) {
                // Handle batch response or empty array (keep-alive?)
                JSONArray arr = new JSONArray(data);
                if (arr.length() > 0 && arr.get(0) instanceof JSONObject) {
                    json = arr.getJSONObject(0); // Process first item for now
                } else {
                    api.logging().logToOutput("Received array response, ignoring: " + data);
                    return;
                }
            } else {
                json = new JSONObject(data);
            }
            
            // 1. Correlation Logic for Proxy
            if (json != null && json.has("id") && !json.isNull("id")) {
                String msgId = json.getString("id");
                if (sessionStore.getRequest(msgId) != null) {
                    api.logging().logToOutput("Engine: Found matching pending request for ID: " + msgId);
                    sessionStore.completeRequest(msgId, json);
                }
            }

            // 2. Enumeration Logic
            if (json != null && json.has("id") && !json.isNull("id")) {
                String id = json.getString("id");
                final JSONObject finalJson = json; // Create final reference for lambdas
                
                // Handshake Response
                if (id.equals(initializeRequestId)) {
                     if (json.has("error")) {
                         api.logging().logToError("Initialization Failed: " + json.getJSONObject("error").toString());
                         if (dashboardTab != null) dashboardTab.setStatus("🔴 Init Failed", java.awt.Color.RED);
                         connectionFailed = true;
                         if (latch != null) latch.countDown();
                         return;
                     }
                     
                     api.logging().logToOutput("Handshake successful. Sending 'notifications/initialized' and starting enumeration.");
                     if (dashboardTab != null) {
                         dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
                         if (json.has("result")) {
                             dashboardTab.updateServerInfo(finalJson.getJSONObject("result"));
                         }
                     }
                     
                     // Signal success to the attemptConnection waiter
                     if (latch != null) latch.countDown();

                     // Send 'notifications/initialized' notification (No ID)
                     JSONObject initializedNotify = new JSONObject();
                     initializedNotify.put("jsonrpc", "2.0");
                     initializedNotify.put("method", "notifications/initialized");
                     sendRequest(initializedNotify.toString());

                     // NOW trigger enumeration
                     toolsRequestId = java.util.UUID.randomUUID().toString();
                     resourcesRequestId = java.util.UUID.randomUUID().toString();
                     promptsRequestId = java.util.UUID.randomUUID().toString();

                     sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"" + toolsRequestId + "\"}");
                     sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"resources/list\",\"id\":\"" + resourcesRequestId + "\"}");
                     sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"prompts/list\",\"id\":\"" + promptsRequestId + "\"}");
                     
                     return;
                }

                if (id.equals(toolsRequestId)) {
                    toolsDone = true;
                    if (json.has("result")) {
                        SwingUtilities.invokeLater(() -> dashboardTab.updateTools(finalJson.getJSONObject("result")));
                    } else if (json.has("error")) {
                         api.logging().logToError("Tools Enumeration Failed: " + json.getJSONObject("error").toString());
                    }
                    checkEnumerationComplete();
                } 
                else if (id.equals(resourcesRequestId)) {
                    resourcesDone = true;
                    if (json.has("result")) {
                        SwingUtilities.invokeLater(() -> dashboardTab.updateResources(finalJson.getJSONObject("result")));
                    } else if (json.has("error")) {
                         api.logging().logToError("Resources Enumeration Failed: " + json.getJSONObject("error").toString());
                    }
                    checkEnumerationComplete();
                } 
                else if (id.equals(promptsRequestId)) {
                    promptsDone = true;
                    if (json.has("result")) {
                        SwingUtilities.invokeLater(() -> dashboardTab.updatePrompts(finalJson.getJSONObject("result")));
                    } else if (json.has("error")) {
                         api.logging().logToError("Prompts Enumeration Failed: " + json.getJSONObject("error").toString());
                    }
                    checkEnumerationComplete();
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to parse event JSON: " + e.getMessage());
            api.logging().logToError("Raw Data was: [" + data + "]");
            
            // Attempt recovery: Sometimes data comes as "data: {json}" but we stripped "data: ".
            // If it's just a raw string like "Connection established", ignore.
            // But if it looks like JSON, maybe we can clean it?
            
            // Critical: If we can't parse it, we must check if it's a response to a pending request.
            // Since we can't parse the ID, we can't correlate it easily.
            // However, we can try to extract ID via regex as a fallback.
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"id\"\s*:\s*\"([^\"]+)\"").matcher(data);
                if (m.find()) {
                    String id = m.group(1);
                    if (sessionStore.getRequest(id) != null) {
                        JSONObject errorResponse = new JSONObject();
                        errorResponse.put("jsonrpc", "2.0");
                        errorResponse.put("id", id);
                        errorResponse.put("error", new JSONObject().put("code", -32700).put("message", "Parse Error: Server returned invalid JSON").put("data", data));
                        sessionStore.completeRequest(id, errorResponse);
                    }
                }
            } catch (Exception ignored) {}
        }
    }
    
    private void checkEnumerationComplete() {
        if (toolsDone && resourcesDone && promptsDone) {
            if (dashboardTab != null) {
                dashboardTab.setStatus("🟢 Connected & Ready", java.awt.Color.GREEN.darker());
            }
        }
    }

    @Override
    public void onClose() {
        api.logging().logToOutput("Transport closed.");
    }

    @Override
    public void onError(Throwable t) {
        connectionFailed = true;
        String errorMsg = (t != null ? t.getMessage() : "Unknown error");
        api.logging().logToError("Transport failure: " + errorMsg);
        
        if (latch != null) latch.countDown();
        
        if (dashboardTab != null) {
            dashboardTab.setStatus("🔴 Failed: " + errorMsg, java.awt.Color.RED);
        }
    }
}
