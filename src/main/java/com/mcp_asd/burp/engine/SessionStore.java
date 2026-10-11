package com.mcp_asd.burp.engine;

import org.json.JSONObject;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class SessionStore {
    // Maps JSON-RPC IDs to CompletableFutures that will hold the response JSON
    private final ConcurrentHashMap<String, CompletableFuture<JSONObject>> pendingRequests = new ConcurrentHashMap<>();

    public void registerRequest(String id, CompletableFuture<JSONObject> future) {
        pendingRequests.put(id, future);
    }

    public CompletableFuture<JSONObject> getRequest(String id) {
        return pendingRequests.get(id);
    }

    public void removeRequest(String id) {
        pendingRequests.remove(id);
    }

    public void completeRequest(String id, JSONObject response) {
        CompletableFuture<JSONObject> future = pendingRequests.remove(id);
        if (future != null) {
            future.complete(response);
        }
    }
}
