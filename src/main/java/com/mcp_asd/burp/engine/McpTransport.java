package com.mcp_asd.burp.engine;

import com.mcp_asd.burp.ui.ConnectionConfiguration;

public interface McpTransport {
    void connect(ConnectionConfiguration config, TransportListener listener);
    void send(String message);
    void close();
}
