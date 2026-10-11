package com.mcp_asd.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
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
        // Only offer the item where there is a request to pull the target from
        if (event.messageEditorRequestResponse().isEmpty() && event.selectedRequestResponses().isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem("Send to MCP-ASD");
        menuItem.addActionListener(e -> {
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() :
                                                  (event.selectedRequestResponses().isEmpty() ? null : event.selectedRequestResponses().get(0));

            if (requestResponse != null) {
                String host = requestResponse.request().httpService().host();
                int port = requestResponse.request().httpService().port();
                boolean secure = requestResponse.request().httpService().secure();

                SwingUtilities.invokeLater(() -> {
                    ConnectionDialog connectionDialog = new ConnectionDialog(api, api.userInterface().swingUtils().suiteFrame(), host, port, secure, null);
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
