package com.mcp_asd.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.engine.EnumerationEngine;
import com.mcp_asd.burp.engine.SessionStore;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcp_asd.burp.scan.McpActiveScanCheck;
import com.mcp_asd.burp.scan.McpPassiveScanCheck;
import com.mcp_asd.burp.ui.DashboardTab;
import com.mcp_asd.burp.ui.McpSettingsPanel;

public class BurpExtender implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        try {
            api.extension().setName("MCP Attack Surface Detector");
            api.logging().logToOutput("MCP Attack Surface Detector loaded.");

            api.logging().logToOutput("Initializing GlobalSettings...");
            GlobalSettings settings = new GlobalSettings(api);

            api.logging().logToOutput("Initializing SessionStore...");
            SessionStore sessionStore = new SessionStore();
            
            // Refactored initialization order to handle circular dependencies
            api.logging().logToOutput("Initializing EnumerationEngine...");
            EnumerationEngine engine = new EnumerationEngine(api, null, sessionStore, settings);

            api.logging().logToOutput("Initializing McpProxy...");
            McpProxy proxy = new McpProxy(api, sessionStore, engine);
            
            api.logging().logToOutput("Initializing DashboardTab...");
            DashboardTab dashboardTab = new DashboardTab(api, proxy, settings);
            
            // Link Tab to Engine
            engine.setDashboardTab(dashboardTab);
            
            // Allow DashboardTab to trigger connection
            dashboardTab.setConnectionListener((config) -> {
                engine.start(config);
            });
            
            // Allow DashboardTab to cancel connection
            dashboardTab.setCancellationListener(() -> {
                engine.cancel();
            });
            
            api.logging().logToOutput("Registering HttpHandler (McpProxy)...");
            api.http().registerHttpHandler(proxy);
            
            registerScanChecks(api, settings);

            api.logging().logToOutput("Registering Settings Panel...");
            api.userInterface().registerSettingsPanel(new McpSettingsPanel(settings));

            api.logging().logToOutput("Registering ContextMenu...");
            api.userInterface().registerContextMenuItemsProvider(new com.mcp_asd.burp.ui.ContextMenuFactory(api, engine));
            
            api.logging().logToOutput("Registering SuiteTab...");
            api.userInterface().registerSuiteTab("MCP-ASD", dashboardTab);
            
            // Register Unload Handler
            api.extension().registerUnloadingHandler(() -> {
                api.logging().logToOutput("Unloading MCP-ASD...");
                engine.shutdown(); // Close active transports and connection threads
                proxy.shutdown(); // Close internal server socket and client threads
                api.logging().logToOutput("Cleanup complete.");
            });
            
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

    /** MCP detection runs as Burp Scanner checks, which are only available in Burp Suite Professional. */
    private static void registerScanChecks(MontoyaApi api, GlobalSettings settings) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            api.logging().logToOutput("Burp Scanner not available in this edition; MCP passive/active detection checks not registered.");
            return;
        }
        api.logging().logToOutput("Registering scan checks...");
        api.scanner().registerPassiveScanCheck(new McpPassiveScanCheck(settings), ScanCheckType.PER_REQUEST);
        api.scanner().registerActiveScanCheck(new McpActiveScanCheck(), ScanCheckType.PER_HOST);
    }
}
