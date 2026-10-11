package com.mcp_asd.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

public class GlobalSettings {
    private final Preferences preferences;
    
    // Key constants
    private static final String KEY_PROXY_TRAFFIC = "mcp_asd.proxy_traffic";
    private static final String KEY_PROXY_HOST = "mcp_asd.proxy_host";
    private static final String KEY_PROXY_PORT = "mcp_asd.proxy_port";
    private static final String KEY_PASSIVE_CHECKS = "mcp_asd.passive_checks";
    private static final String KEY_IGNORE_TLS_ERRORS = "mcp_asd.ignore_tls_errors";

    // Defaults
    private static final boolean DEFAULT_PROXY_TRAFFIC = true;
    private static final String DEFAULT_PROXY_HOST = "127.0.0.1";
    private static final int DEFAULT_PROXY_PORT = 8080;
    private static final boolean DEFAULT_PASSIVE_CHECKS = true;
    private static final boolean DEFAULT_IGNORE_TLS_ERRORS = false;

    public GlobalSettings(MontoyaApi api) {
        this.preferences = api.persistence().preferences();
    }

    public boolean isProxyTrafficEnabled() {
        return preferences.getBoolean(KEY_PROXY_TRAFFIC) == null ? DEFAULT_PROXY_TRAFFIC : preferences.getBoolean(KEY_PROXY_TRAFFIC);
    }

    public void setProxyTrafficEnabled(boolean enabled) {
        preferences.setBoolean(KEY_PROXY_TRAFFIC, enabled);
    }

    public String getProxyHost() {
        return preferences.getString(KEY_PROXY_HOST) == null ? DEFAULT_PROXY_HOST : preferences.getString(KEY_PROXY_HOST);
    }

    public void setProxyHost(String host) {
        preferences.setString(KEY_PROXY_HOST, host);
    }

    public int getProxyPort() {
        return preferences.getInteger(KEY_PROXY_PORT) == null ? DEFAULT_PROXY_PORT : preferences.getInteger(KEY_PROXY_PORT);
    }

    public void setProxyPort(int port) {
        preferences.setInteger(KEY_PROXY_PORT, port);
    }

    public boolean isPassiveChecksEnabled() {
        return preferences.getBoolean(KEY_PASSIVE_CHECKS) == null ? DEFAULT_PASSIVE_CHECKS : preferences.getBoolean(KEY_PASSIVE_CHECKS);
    }

    public void setPassiveChecksEnabled(boolean enabled) {
        preferences.setBoolean(KEY_PASSIVE_CHECKS, enabled);
    }

    /** Direct (non-proxied) SSE/WebSocket connections only; proxied traffic trusts Burp's CA. */
    public boolean isIgnoreTlsErrorsEnabled() {
        return preferences.getBoolean(KEY_IGNORE_TLS_ERRORS) == null ? DEFAULT_IGNORE_TLS_ERRORS : preferences.getBoolean(KEY_IGNORE_TLS_ERRORS);
    }

    public void setIgnoreTlsErrorsEnabled(boolean enabled) {
        preferences.setBoolean(KEY_IGNORE_TLS_ERRORS, enabled);
    }
}
