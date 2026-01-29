package com.mcp_asd.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.menu.MenuItem;
import com.mcp_asd.burp.engine.EnumerationEngine;

import javax.swing.*;
import java.awt.Component;
import java.util.Collections;
import java.util.List;

public class ContextMenuFactory implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final EnumerationEngine engine;

    public ContextMenuFactory(MontoyaApi api, EnumerationEngine engine) {
        this.api = api;
        this.engine = engine;
    }

    @Override
    public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
        JMenuItem menuItem = new JMenuItem("Send to MCP-ASD");
        menuItem.addActionListener(e -> {
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : 
                                                  (event.selectedRequestResponses().isEmpty() ? null : event.selectedRequestResponses().get(0));
            
            if (requestResponse != null) {
                String host = requestResponse.request().httpService().host();
                int port = requestResponse.request().httpService().port();
                
                SwingUtilities.invokeLater(() -> {
                    // Just pass null as owner or use a dummy frame.
                    // Actually, Montoya doesn't expose the main frame easily. We can use null.
                    ConnectionDialog connectionDialog = new ConnectionDialog(null, host, port, null);
                    connectionDialog.setVisible(true);
                    
                    if (connectionDialog.isConfirmed()) {
                        engine.start(connectionDialog.getConfiguration());
                    }
                });
            }
        });

        return Collections.singletonList(menuItem);
    }
}
