package com.mcp_asd.burp.ui;

import java.util.HashMap;
import java.util.Map;

public class ConnectionConfiguration {
    private String host;
    private int port;
    private String transport;
    private String path;
    
    private Map<String, String> headers = new HashMap<>();
    
    private boolean useMtls;
    private String clientCertPath;
    private String clientCertPassword;

    public ConnectionConfiguration(String host, int port, String transport, String path) {
        this.host = host;
        this.port = port;
        this.transport = transport;
        this.path = path;
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getTransport() { return transport; }
    public String getPath() { return path; }

    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { this.headers = headers; }
    public void addHeader(String key, String value) { this.headers.put(key, value); }

    public boolean isUseMtls() { return useMtls; }
    public void setUseMtls(boolean useMtls) { this.useMtls = useMtls; }

    public String getClientCertPath() { return clientCertPath; }
    public void setClientCertPath(String clientCertPath) { this.clientCertPath = clientCertPath; }

    public String getClientCertPassword() { return clientCertPassword; }
    public void setClientCertPassword(String clientCertPassword) { this.clientCertPassword = clientCertPassword; }
}
