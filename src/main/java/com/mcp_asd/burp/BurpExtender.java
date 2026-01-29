package com.mcp_asd.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.engine.EnumerationEngine;
import com.mcp_asd.burp.engine.SessionStore;
import com.mcp_asd.burp.test.SecurityTester;
import com.mcp_asd.burp.ui.DashboardTab;

public class BurpExtender implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        try {
            api.extension().setName("MCP Attack Surface Detector");
            api.logging().logToOutput("MCP Attack Surface Detector loaded.");

            api.logging().logToOutput("Initializing SessionStore...");
            SessionStore sessionStore = new SessionStore();
            
            api.logging().logToOutput("Initializing SecurityTester...");
            SecurityTester tester = new SecurityTester(api);
            tester.setSessionStore(sessionStore);
            
            // Refactored initialization order to handle circular dependencies
            api.logging().logToOutput("Initializing EnumerationEngine...");
            EnumerationEngine engine = new EnumerationEngine(api, null, tester, sessionStore);
            tester.setEngine(engine);

            api.logging().logToOutput("Initializing McpProxy...");
            McpProxy proxy = new McpProxy(api, sessionStore, engine);
            
            api.logging().logToOutput("Initializing DashboardTab...");
            DashboardTab dashboardTab = new DashboardTab(api, tester, proxy);
            
            // Link Tab to Engine
            engine.setDashboardTab(dashboardTab);
            
            // Allow DashboardTab to trigger connection
            dashboardTab.setConnectionListener((config) -> {
                engine.start(config);
            });
            
            api.logging().logToOutput("Registering HttpHandler...");

            api.logging().logToOutput("Registering HttpHandler...");
            api.http().registerHttpHandler(proxy);
            
            api.logging().logToOutput("Registering ContextMenu...");
            api.userInterface().registerContextMenuItemsProvider(new com.mcp_asd.burp.ui.ContextMenuFactory(api, engine));
            
            api.logging().logToOutput("Registering SuiteTab...");
            api.userInterface().registerSuiteTab("MCP-ASD", dashboardTab);
            
            api.logging().logToOutput("Initialization complete.");
        } catch (Throwable e) {
            api.logging().logToError("Fatal error during initialization: " + e.getMessage());
            e.printStackTrace(); // This might go to stdout/stderr which Burp captures
            // Also try to log stack trace to Burp error log
            java.io.StringWriter sw = new java.io.StringWriter();
            java.io.PrintWriter pw = new java.io.PrintWriter(sw);
            e.printStackTrace(pw);
            api.logging().logToError(sw.toString());
        }
    }
}