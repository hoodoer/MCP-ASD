package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.DashboardTab;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.swing.SwingUtilities;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
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
    // Tracked, daemon connection threads so an unload can stop them
    private final ExecutorService connectionExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "MCP-ASD-Connection");
        t.setDaemon(true);
        return t;
    });
    
    // Advertised protocol versions per transport (most recent standard supporting it).
    private static final String PROTOCOL_VERSION_STREAMABLE = "2026-07-28";
    private static final String PROTOCOL_VERSION_LEGACY = "2024-11-05";
    private String advertisedVersion; // what initialize advertised (per transport)
    private String acceptedVersion;   // what the server accepted (null = none returned)

    // Request IDs for tracking handshake + enumeration responses
    private String discoverRequestId;
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

    /** Called on extension unload: closes the transport and stops any connection attempt. */
    public void shutdown() {
        cancel();
        connectionExecutor.shutdownNow();
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
        
        try {
            connectionExecutor.submit(() -> connect(config));
        } catch (RejectedExecutionException e) {
            api.logging().logToError("Connection not started: extension is unloading.");
        }
    }

    private void connect(ConnectionConfiguration config) {
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
            } else if ("Streamable HTTP".equals(config.getTransport())) {
                StreamableHttpTransport sh = new StreamableHttpTransport(api, settings);
                if (forceHttp1) sh.setForceHttp1(true);
                sh.setAdvertisedVersion(advertisedVersionFor(config.getTransport()));
                transport = sh;
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

        String transportName = currentConfig != null ? currentConfig.getTransport() : "";
        advertisedVersion = advertisedVersionFor(transportName);

        if ("Streamable HTTP".equals(transportName)) {
            // Discover-first probe (spec 2026-07-28: servers MUST implement
            // server/discover). The transport supplies the modern headers and
            // _meta from its 2026 pre-handshake seed; a legacy server answers a
            // non-modern error and the engine falls back to initialize.
            discoverRequestId = java.util.UUID.randomUUID().toString();
            JSONObject discoverRequest = new JSONObject();
            discoverRequest.put("jsonrpc", "2.0");
            discoverRequest.put("method", "server/discover");
            discoverRequest.put("params", new JSONObject());
            discoverRequest.put("id", discoverRequestId);

            api.logging().logToOutput("Sending server/discover probe (protocolVersion " + advertisedVersion + ")");
            sendRequest(discoverRequest.toString());
        } else {
            sendInitialize();
        }
    }

    /** Build and send the classic initialize handshake request. */
    private void sendInitialize() {
        JSONObject initParams = new JSONObject();
        initParams.put("protocolVersion", advertisedVersion);
        initParams.put("capabilities", new JSONObject());
        initParams.put("clientInfo", new JSONObject().put("name", "MCP-ASD").put("version", "1.3.0"));

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

        api.logging().logToOutput("Sending initialize (advertised protocolVersion " + advertisedVersion + ")");
        sendRequest(initRequest.toString());
    }

    /** Most recent MCP standard that supports the given transport (per-transport version table). */
    private String advertisedVersionFor(String transportName) {
        return "Streamable HTTP".equals(transportName) ? PROTOCOL_VERSION_STREAMABLE : PROTOCOL_VERSION_LEGACY;
    }

    /** True when a JSON-RPC error code is in the MCP spec-reserved modern range (-32020..-32099). */
    private static boolean isModernErrorCode(int code) {
        return code >= -32099 && code <= -32020;
    }

    /**
     * Reads a supported-versions list from a server/discover result
     * ({@code result.supportedVersions}) or a JSON-RPC error
     * ({@code error.data.supported}, {@code error.data} as a bare array, or
     * {@code error.supported}). Returns null when no recognizable list is present.
     */
    private static JSONArray readVersionList(JSONObject payload) {
        try {
            if (payload == null) return null;
            if (payload.has("supportedVersions") && payload.get("supportedVersions") instanceof JSONArray arr) return arr;
            if (payload.has("supported") && payload.get("supported") instanceof JSONArray arr) return arr;
            if (payload.has("data")) {
                Object data = payload.get("data");
                if (data instanceof JSONArray arr) return arr;
                if (data instanceof JSONObject dataObj
                        && dataObj.has("supported") && dataObj.get("supported") instanceof JSONArray arr) {
                    return arr;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Splits a version list into [newest modern revision (≥ 2026-07-28),
     * newest legacy revision] — either element may be null (issue 0005 ladder).
     */
    private static String[] splitModernLegacy(JSONArray versions) {
        String modern = null;
        String legacy = null;
        if (versions != null) {
            for (int i = 0; i < versions.length(); i++) {
                String v = versions.optString(i, null);
                if (v == null) continue;
                v = v.trim();
                if (v.isEmpty()) continue;
                if (v.compareTo("2026-07-28") >= 0) {
                    if (modern == null || v.compareTo(modern) > 0) modern = v;
                } else if (legacy == null || v.compareTo(legacy) > 0) {
                    legacy = v;
                }
            }
        }
        return new String[]{modern, legacy};
    }

    /**
     * If a modern error carries no version list but names a modern version in
     * its data (e.g. HeaderMismatch), return it; otherwise null.
     */
    private static String namedModernVersion(JSONObject error) {
        try {
            if (error != null && error.has("data")) {
                Object data = error.get("data");
                String candidate = null;
                if (data instanceof String s) {
                    candidate = s.trim();
                } else if (data instanceof JSONObject dataObj) {
                    for (String key : new String[]{"protocolVersion", "expected", "version"}) {
                        if (dataObj.has(key) && dataObj.get(key) instanceof String s) {
                            candidate = s.trim();
                            break;
                        }
                    }
                }
                if (candidate != null && candidate.matches("\\d{4}-\\d{2}-\\d{2}") && candidate.compareTo("2026-07-28") >= 0) {
                    return candidate;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Reseed the advertised version on the engine and (Streamable HTTP) transport before a probe. */
    private void reseedAdvertised(String version) {
        advertisedVersion = version;
        if (transport instanceof StreamableHttpTransport sh) {
            sh.setAdvertisedVersion(version);
        }
    }

    /**
     * Downgrade ladder for the server/discover probe response:
     * decides modern vs. legacy era and the version to run at, then proceeds —
     * modern: adopt the version, push it to the transport, and enumerate (no
     * initialize, no notifications/initialized); legacy: reseed the transport
     * to the newest listed legacy revision (or the legacy seed) and run the
     * classic initialize handshake.
     */
    private void handleDiscoverResponse(JSONObject json) {
        JSONObject error = json.has("error") && json.get("error") instanceof JSONObject e ? e : null;
        JSONObject result = json.has("result") && json.get("result") instanceof JSONObject r ? r : null;

        JSONArray versions = null;
        boolean recognizedModern = false;
        if (result != null) {
            // A server that answers server/discover implements the modern method.
            recognizedModern = true;
            versions = readVersionList(result);
        } else if (error != null) {
            recognizedModern = isModernErrorCode(error.optInt("code", 0));
            versions = readVersionList(error);
        }

        String[] split = splitModernLegacy(versions);
        String modern = split[0];
        String legacy = split[1];

        if (modern != null) {
            if (result != null) {
                api.logging().logToOutput("Modern MCP server: server/discover confirmed a modern server (supportedVersions: "
                        + versions + "); adopting " + modern);
            } else {
                api.logging().logToOutput("Modern MCP server rejected the probe (error: " + error + "); adopting " + modern);
            }
            acceptedVersion = modern;
            advertisedVersion = modern;
            if (transport != null) transport.setProtocolVersion(modern);
            logAcceptedVersion("modern server, no handshake");
            if (dashboardTab != null) dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
            showDiscoverServerInfo(result, modern);
            if (latch != null) latch.countDown();
            beginEnumeration(false);
            return;
        }

        if (recognizedModern && legacy != null) {
            api.logging().logToOutput("Modern MCP server lists only legacy revisions"
                    + (error != null ? " (error: " + error + ")" : "")
                    + "; downgrading to " + legacy + " and re-handshaking");
            reseedAdvertised(legacy);
            sendInitialize();
            return;
        }

        if (recognizedModern) {
            // Modern signal without a usable version list (e.g. -32020 HeaderMismatch):
            // the server rejected the request shape, not the version — stay modern,
            // at the version the error names (if any) or the advertised one.
            String named = error != null ? namedModernVersion(error) : null;
            String target = named != null ? named
                    : (advertisedVersion != null && advertisedVersion.compareTo("2026-07-28") >= 0
                            ? advertisedVersion : PROTOCOL_VERSION_STREAMABLE);
            api.logging().logToOutput("Modern MCP server (no supported list in response"
                    + (error != null ? "; error: " + error : "") + "); continuing at " + target);
            acceptedVersion = target;
            advertisedVersion = target;
            if (transport != null) transport.setProtocolVersion(target);
            logAcceptedVersion("modern server, no handshake");
            if (dashboardTab != null) dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
            if (latch != null) latch.countDown();
            beginEnumeration(false);
            return;
        }

        // Legacy server (404/-32601, empty or non-modern body, unrecognized error):
        // fall back to the classic initialize handshake at the legacy seed.
        api.logging().logToOutput("Falling back to legacy initialize (probe "
                + (error != null ? "answered " + error : "got no recognizable modern response")
                + "; advertising " + PROTOCOL_VERSION_LEGACY + ")");
        reseedAdvertised(PROTOCOL_VERSION_LEGACY);
        sendInitialize();
    }

    /** Populate the dashboard Server Info from a server/discover result (serverInfo lives in result._meta). */
    private void showDiscoverServerInfo(JSONObject result, String version) {
        if (dashboardTab == null || result == null) return;
        JSONObject info = new JSONObject();
        info.put("protocolVersion", version);
        if (result.has("capabilities") && result.get("capabilities") instanceof JSONObject) {
            info.put("capabilities", result.get("capabilities"));
        }
        if (result.has("instructions") && result.get("instructions") instanceof String) {
            info.put("instructions", result.get("instructions"));
        }
        JSONObject meta = result.optJSONObject("_meta");
        if (meta != null && meta.has("io.modelcontextprotocol/serverInfo")) {
            info.put("serverInfo", meta.get("io.modelcontextprotocol/serverInfo"));
        }
        SwingUtilities.invokeLater(() -> dashboardTab.updateServerInfo(info));
    }

    /** Log the accepted protocol version and flag a downgrade vs what was advertised. */
    private void logAcceptedVersion(String context) {
        if (acceptedVersion == null) {
            api.logging().logToOutput("Protocol version: server returned none (legacy-era behavior); " + context + ".");
        } else if (acceptedVersion.equals(advertisedVersion)) {
            api.logging().logToOutput("Protocol version: " + acceptedVersion + " (as advertised); " + context + ".");
        } else {
            api.logging().logToOutput("Protocol version downgraded: advertised " + advertisedVersion
                    + ", server accepted " + acceptedVersion + "; " + context + ".");
        }
    }

    /**
     * Start enumeration. notifications/initialized goes out only after a legacy
     * handshake — the 2026 revision defines no client→server notifications over
     * Streamable HTTP.
     */
    private void beginEnumeration(boolean legacyHandshake) {
        if (legacyHandshake) {
            // Send 'notifications/initialized' notification (No ID)
            JSONObject initializedNotify = new JSONObject();
            initializedNotify.put("jsonrpc", "2.0");
            initializedNotify.put("method", "notifications/initialized");
            sendRequest(initializedNotify.toString());
        }

        // NOW trigger enumeration
        toolsRequestId = java.util.UUID.randomUUID().toString();
        resourcesRequestId = java.util.UUID.randomUUID().toString();
        promptsRequestId = java.util.UUID.randomUUID().toString();

        sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"" + toolsRequestId + "\"}");
        sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"resources/list\",\"id\":\"" + resourcesRequestId + "\"}");
        sendRequest("{\"jsonrpc\":\"2.0\",\"method\":\"prompts/list\",\"id\":\"" + promptsRequestId + "\"}");
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
                
                  // Discover probe response (Streamable HTTP, modern-era probe)
                  if (id.equals(discoverRequestId)) {
                      handleDiscoverResponse(finalJson);
                      return;
                  }

                  // Handshake Response
                  if (id.equals(initializeRequestId)) {
                       if (json.has("error")) {
                           JSONObject error = json.getJSONObject("error");
                           // Downgrade ladder (issue 0005): an initialize error is processed the
                           // same way as a discover response — modern signal → modern regime at
                           // the newest listed modern version; a legacy-only list → re-handshake
                           // at the newest listed revision.
                           String[] split = splitModernLegacy(readVersionList(error));
                           if (split[0] != null) {
                               api.logging().logToOutput("Modern MCP server rejected initialize (error: " + error.toString()
                                       + "); adopting " + split[0] + " with per-request version declaration.");
                               acceptedVersion = split[0];
                               advertisedVersion = split[0];
                               if (transport != null) transport.setProtocolVersion(split[0]);
                               logAcceptedVersion("modern server, no handshake");
                               if (dashboardTab != null) dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
                               if (latch != null) latch.countDown();
                               beginEnumeration(false);
                               return;
                           }
                           if (isModernErrorCode(error.optInt("code", 0))) {
                               String named = namedModernVersion(error);
                               String target = named != null ? named
                                       : (advertisedVersion != null && advertisedVersion.compareTo("2026-07-28") >= 0
                                               ? advertisedVersion : PROTOCOL_VERSION_STREAMABLE);
                               api.logging().logToOutput("Modern MCP server rejected initialize (error: " + error.toString()
                                       + "); continuing at " + target + " with per-request version declaration.");
                               acceptedVersion = target;
                               advertisedVersion = target;
                               if (transport != null) transport.setProtocolVersion(target);
                               logAcceptedVersion("modern server, no handshake");
                               if (dashboardTab != null) dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
                               if (latch != null) latch.countDown();
                               beginEnumeration(false);
                               return;
                           }
                           if (split[1] != null) {
                               api.logging().logToOutput("Server rejected initialize and named legacy revisions (error: " + error.toString()
                                       + "); re-handshaking at " + split[1]);
                               reseedAdvertised(split[1]);
                               sendInitialize();
                               return;
                           }
                           api.logging().logToError("Initialization Failed: " + error.toString());
                           if (dashboardTab != null) dashboardTab.setStatus("🔴 Init Failed", java.awt.Color.RED);
                           connectionFailed = true;
                           if (latch != null) latch.countDown();
                           return;
                       }

                      // Legacy path: the server answered initialize — every protocol version it
                      // returns is accepted (absent = null/legacy) and pushed to the transport.
                      acceptedVersion = null;
                      if (json.has("result") && json.get("result") instanceof JSONObject result
                              && result.has("protocolVersion")) {
                          acceptedVersion = result.getString("protocolVersion");
                      }
                      if (transport != null) transport.setProtocolVersion(acceptedVersion);
                      logAcceptedVersion("handshake successful");

                      api.logging().logToOutput("Handshake successful. Sending 'notifications/initialized' and starting enumeration.");
                      if (dashboardTab != null) {
                          dashboardTab.setStatus("🔵 Enumerating...", java.awt.Color.BLUE.darker());
                          if (json.has("result")) {
                              dashboardTab.updateServerInfo(finalJson.getJSONObject("result"));
                          }
                      }

                       // Signal success to the attemptConnection waiter
                       if (latch != null) latch.countDown();

                       beginEnumeration(true);
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
