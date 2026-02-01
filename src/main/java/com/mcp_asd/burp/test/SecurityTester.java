package com.mcp_asd.burp.test;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.engine.EnumerationEngine;
import com.mcp_asd.burp.engine.SessionStore;
import com.mcp_asd.burp.ui.AttackSurfaceNode;
import org.json.JSONObject;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class SecurityTester {
    private final MontoyaApi api;
    private EnumerationEngine engine;
    private SessionStore sessionStore;

    public SecurityTester(MontoyaApi api) {
        this.api = api;
    }

    public void setEngine(EnumerationEngine engine) {
        this.engine = engine;
    }

    public void setSessionStore(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    public void scanTool(AttackSurfaceNode node) {
        new Thread(() -> {
            api.logging().logToOutput("Starting security scan for tool: " + node.toString());
            JSONObject itemData = node.getData();
            JSONObject inputSchema = itemData.optJSONObject("inputSchema");
            
            if (inputSchema == null || !inputSchema.has("properties")) {
                api.logging().logToOutput("No parameters to scan for tool: " + node.toString());
                return;
            }

            JSONObject properties = inputSchema.getJSONObject("properties");
            for (String paramName : properties.keySet()) {
                JSONObject paramDef = properties.getJSONObject(paramName);
                String type = paramDef.optString("type", "string");

                // 1. Type Confusion Test
                performTypeConfusion(node.toString(), paramName, type);
                
                // 2. Simple Injection Probing (if string)
                if ("string".equals(type)) {
                    performInjectionProbe(node.toString(), paramName);
                }
            }
            api.logging().logToOutput("Scan complete for tool: " + node.toString());
        }).start();
    }

    public void scanResource(AttackSurfaceNode node) {
        new Thread(() -> {
            String uri = node.getData().optString("uri");
            if (uri == null || uri.isEmpty()) {
                api.logging().logToOutput("No URI found for resource: " + node.toString());
                return;
            }

            api.logging().logToOutput("Starting BOLA scan for resource: " + uri);

            // 1. Identify Numeric Segments
            // Regex to find integers. We will iterate the last integer found in the URI.
            // e.g. file:///logs/123 -> Try 122, 124
            java.util.regex.Pattern p = java.util.regex.Pattern.compile("(\\d+)");
            java.util.regex.Matcher m = p.matcher(uri);

            boolean foundNumber = false;
            // Find the last match to target the ID usually at the end
            java.util.regex.MatchResult lastMatch = null;
            while (m.find()) {
                lastMatch = m.toMatchResult();
                foundNumber = true;
            }

            if (!foundNumber) {
                api.logging().logToOutput("No numeric ID found in URI to iterate: " + uri);
                return;
            }

            int originalId = Integer.parseInt(lastMatch.group(1));
            int start = lastMatch.start(1);
            int end = lastMatch.end(1);

            // Test ID - 1 and ID + 1
            int[] testIds = { originalId - 1, originalId + 1 };

            for (int testId : testIds) {
                if (testId < 0) continue; // Skip negative IDs for now

                String prefix = uri.substring(0, start);
                String suffix = uri.substring(end);
                String testUri = prefix + testId + suffix;

                api.logging().logToOutput("Testing BOLA URI: " + testUri);
                performBolaCheck(testUri);
            }
            
            api.logging().logToOutput("BOLA Scan complete for: " + uri);

        }).start();
    }

    private void performBolaCheck(String testUri) {
        JSONObject request = new JSONObject();
        request.put("jsonrpc", "2.0");
        String id = java.util.UUID.randomUUID().toString();
        request.put("id", id);
        request.put("method", "resources/read");
        request.put("params", new JSONObject().put("uri", testUri));

        JSONObject response = sendAndWait(request);

        if (response != null) {
            if (response.has("result")) {
                JSONObject result = response.getJSONObject("result");
                if (result.has("contents")) {
                    org.json.JSONArray contents = result.getJSONArray("contents");
                    if (contents.length() > 0) {
                        api.logging().logToError("VULNERABILITY SUSPECTED: Accessible Unadvertised Resource (BOLA)");
                        api.logging().logToError("Original URI was mutated to: " + testUri);
                        api.logging().logToError("Server returned " + contents.length() + " content blobs.");
                    }
                }
            } else if (response.has("error")) {
                // Expected behavior for secure endpoints
                // api.logging().logToOutput("Access denied/not found for " + testUri + " (Good)");
            }
        }
    }

    private void performTypeConfusion(String toolName, String paramName, String expectedType) {
        Object badValue;
        if ("integer".equals(expectedType) || "number".equals(expectedType)) {
            badValue = "not_a_number_string";
        } else {
            badValue = 12345; // Send integer where string/object expected
        }

        api.logging().logToOutput("Testing Type Confusion on [" + paramName + "] (Expected " + expectedType + ", Sending " + badValue.getClass().getSimpleName() + ")");
        
        JSONObject request = createInvokeRequest(toolName, paramName, badValue);
        JSONObject response = sendAndWait(request);
        
        if (response != null && response.has("error")) {
            JSONObject error = response.getJSONObject("error");
            if (error.optInt("code") == -32603 || error.optString("message").toLowerCase().contains("stacktrace")) {
                api.logging().logToError("VULNERABILITY FOUND: Potential Type Confusion crash/leak on parameter [" + paramName + "]");
                api.logging().logToError("Response: " + response.toString());
            }
        }
    }

    private void performInjectionProbe(String toolName, String paramName) {
        String payload = "{{7*7}}'\"<script>alert(1)</script>";
        api.logging().logToOutput("Testing Injection Probe on [" + paramName + "] with payload: " + payload);

        JSONObject request = createInvokeRequest(toolName, paramName, payload);
        JSONObject response = sendAndWait(request);

        if (response != null && response.has("result")) {
            String resultStr = response.getJSONObject("result").toString();
            if (resultStr.contains("49") || resultStr.contains("<script>")) {
                api.logging().logToError("VULNERABILITY FOUND: Potential Reflection/Injection on parameter [" + paramName + "]");
                api.logging().logToError("Response reflects payload!");
            }
        }
    }

    private JSONObject createInvokeRequest(String toolName, String paramName, Object value) {
        JSONObject request = new JSONObject();
        request.put("jsonrpc", "2.0");
        String id = java.util.UUID.randomUUID().toString();
        request.put("id", id);
        request.put("method", "tools/call");

        JSONObject params = new JSONObject();
        params.put("name", toolName);
        
        JSONObject arguments = new JSONObject();
        arguments.put(paramName, value);
        params.put("arguments", arguments);
        
        request.put("params", params);
        return request;
    }

    private JSONObject sendAndWait(JSONObject request) {
        String id = request.getString("id");
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        sessionStore.registerRequest(id, future);
        
        engine.sendRequest(request.toString());
        
        try {
            return future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            api.logging().logToError("Scan request timed out for ID: " + id);
            return null;
        }
    }
}
