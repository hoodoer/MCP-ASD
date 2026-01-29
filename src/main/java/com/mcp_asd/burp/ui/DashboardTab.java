package com.mcp_asd.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcp_asd.burp.test.SecurityTester;
import com.mcp_asd.burp.McpProxy; // Add import
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class DashboardTab extends JComponent {
    private final MontoyaApi api;
    private final SecurityTester tester;
    private final McpProxy mcpProxy;
    private ConnectionListener connectionListener;

    public interface ConnectionListener {
        void onConnect(ConnectionConfiguration config);
    }

    public void setConnectionListener(ConnectionListener listener) {
        this.connectionListener = listener;
    }
    
    // Lists for the 3 primitives
    private DefaultListModel<AttackSurfaceNode> toolsModel;
    private DefaultListModel<AttackSurfaceNode> resourcesModel;
    private DefaultListModel<AttackSurfaceNode> promptsModel;
    
    private JList<AttackSurfaceNode> toolsList;
    private JList<AttackSurfaceNode> resourcesList;
    private JList<AttackSurfaceNode> promptsList;

    private JLabel headerLabel;
    private JLabel statusLabel; // New status label
    private JTextArea metadataInspector;
    private JButton sendToRepeaterButton;
    private JButton sendToIntruderButton;
    
    private String targetHost;
    private int targetPort;
    private ConnectionConfiguration lastConfig; // Persist last config

    public DashboardTab(MontoyaApi api, SecurityTester tester, McpProxy mcpProxy) {
        this.api = api;
        this.tester = tester;
        this.mcpProxy = mcpProxy;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        // --- TOP PANEL: Header & About ---
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        JPanel titlePanel = new JPanel(new GridLayout(2, 1));
        headerLabel = new JLabel("Target: Not Connected");
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        
        statusLabel = new JLabel("⚪ Status: Idle");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 12f));
        
        titlePanel.add(headerLabel);
        titlePanel.add(statusLabel);
        
        JButton aboutButton = new JButton("About");
        aboutButton.addActionListener(e -> JOptionPane.showMessageDialog(this, 
                "MCP Attack Surface Detector\n\nA Burp Suite extension for discovering and testing\nModel Context Protocol (MCP) servers.\n\nVersion: 1.0\nAuthor: Hoodoer", 
                "About MCP-ASD", 
                JOptionPane.INFORMATION_MESSAGE));

        JButton connectButton = new JButton("New Connection");
        connectButton.addActionListener(e -> {
            SwingUtilities.invokeLater(() -> {
                ConnectionDialog dialog = new ConnectionDialog(null, "localhost", 8000, lastConfig);
                dialog.setVisible(true);
                if (dialog.isConfirmed()) {
                    lastConfig = dialog.getConfiguration(); // Save it
                    if (connectionListener != null) {
                        connectionListener.onConnect(lastConfig);
                    }
                }
            });
        });

        JPanel headerButtons = new JPanel();
        headerButtons.add(connectButton);
        headerButtons.add(aboutButton);

        topPanel.add(titlePanel, BorderLayout.WEST);
        topPanel.add(headerButtons, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);


        // --- LEFT PANEL: The 3 Primitives (Tools, Resources, Prompts) ---
        // We use a JPanel with GridLayout(3, 1) to stack them vertically with equal height
        JPanel primitivesPanel = new JPanel(new GridLayout(3, 1, 0, 10));
        primitivesPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10)); // Margin

        // Tools Pane
        toolsModel = new DefaultListModel<>();
        toolsList = createPrimitiveList(toolsModel, "Tools");
        JScrollPane toolsScroll = new JScrollPane(toolsList);
        toolsScroll.setBorder(BorderFactory.createTitledBorder(null, "🛠️ Tools", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("SansSerif", Font.BOLD, 12)));
        primitivesPanel.add(toolsScroll);

        // Resources Pane
        resourcesModel = new DefaultListModel<>();
        resourcesList = createPrimitiveList(resourcesModel, "Resources");
        JScrollPane resourcesScroll = new JScrollPane(resourcesList);
        resourcesScroll.setBorder(BorderFactory.createTitledBorder(null, "📄 Resources", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("SansSerif", Font.BOLD, 12)));
        primitivesPanel.add(resourcesScroll);

        // Prompts Pane
        promptsModel = new DefaultListModel<>();
        promptsList = createPrimitiveList(promptsModel, "Prompts");
        JScrollPane promptsScroll = new JScrollPane(promptsList);
        promptsScroll.setBorder(BorderFactory.createTitledBorder(null, "💬 Prompts", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("SansSerif", Font.BOLD, 12)));
        primitivesPanel.add(promptsScroll);

        addContextMenu(toolsList, "Tools");
        addContextMenu(resourcesList, "Resources");

        // --- RIGHT PANEL: Details & Actions ---
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("Request Prototype / Details"));
        
        metadataInspector = new JTextArea("Select an item on the left to generate a request...");
        rightPanel.add(new JScrollPane(metadataInspector), BorderLayout.CENTER);

        sendToRepeaterButton = new JButton("Send to Repeater");
        sendToRepeaterButton.setEnabled(false);
        sendToRepeaterButton.addActionListener(e -> sendTo(false));

        sendToIntruderButton = new JButton("Send to Intruder");
        sendToIntruderButton.setEnabled(false);
        sendToIntruderButton.addActionListener(e -> sendTo(true));
        
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(sendToRepeaterButton);
        buttonPanel.add(sendToIntruderButton);
        rightPanel.add(buttonPanel, BorderLayout.SOUTH);

        // --- SPLIT PANE ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, primitivesPanel, rightPanel);
        splitPane.setResizeWeight(0.4); // Left side takes 40%

        add(splitPane, BorderLayout.CENTER);
    }

    private JList<AttackSurfaceNode> createPrimitiveList(DefaultListModel<AttackSurfaceNode> model, String type) {
        JList<AttackSurfaceNode> list = new JList<>(model);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !list.isSelectionEmpty()) {
                // When selecting in one list, clear others to avoid confusion? 
                // Or just show details for the latest selection. 
                // Let's clear others for clarity.
                if (list == toolsList) { resourcesList.clearSelection(); promptsList.clearSelection(); }
                if (list == resourcesList) { toolsList.clearSelection(); promptsList.clearSelection(); }
                if (list == promptsList) { toolsList.clearSelection(); resourcesList.clearSelection(); }

                updateDetails(list.getSelectedValue(), type);
            }
        });
        return list;
    }

    private void updateDetails(AttackSurfaceNode node, String type) {
        if (node == null) return;
        String prototype = generatePrototypeRequest(node, type);
        metadataInspector.setText(prototype);
        metadataInspector.setCaretPosition(0);
        sendToRepeaterButton.setEnabled(true);
        sendToIntruderButton.setEnabled(true);
    }

    public void setStatus(String status, Color color) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
            statusLabel.setForeground(color);
        });
    }

    public void setTarget(String host, int port) {
        this.targetHost = host;
        this.targetPort = port;
        SwingUtilities.invokeLater(() -> headerLabel.setText("Connected to: " + host + ":" + port));
    }

    // New update methods for separate categories
    public void updateTools(JSONObject result) {
        updateModel(toolsModel, result);
    }
    
    public void updateResources(JSONObject result) {
        updateModel(resourcesModel, result);
    }
    
    public void updatePrompts(JSONObject result) {
        updateModel(promptsModel, result);
    }

    private void updateModel(DefaultListModel<AttackSurfaceNode> model, JSONObject result) {
        // We assume result is the "result" object from MCP (which might contain "tools": [...])
        // Or if using the map-based heuristic:
        // We need to parse whatever updateTreeWithBranch was parsing.
        
        model.clear();
        // Check for Standard Spec first: { "tools": [ ... ] } or { "resources": [...] }
        // The key name isn't passed here, so we iterate keys
        
        // Actually, EnumerationEngine passes the inner result.
        // Let's try to handle both Array and Map formats genericly
        
        if (result.keySet().isEmpty()) return;

        // Try to find the main array key (tools/resources/prompts)
        String mainKey = null;
        if (result.has("tools")) mainKey = "tools";
        else if (result.has("resources")) mainKey = "resources";
        else if (result.has("prompts")) mainKey = "prompts";

        if (mainKey != null) {
            // Standard Spec
            JSONArray items = result.getJSONArray(mainKey);
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                String displayName = item.optString("name", item.optString("uri", "Unknown"));
                model.addElement(new AttackSurfaceNode(displayName, item));
            }
        } else {
            // Map-based fallback (for our simple python server if it sends that way)
            // Iterate all keys
             for (String itemName : result.keySet()) {
                Object val = result.get(itemName);
                if (val instanceof JSONObject) {
                    JSONObject item = (JSONObject) val;
                    if (!item.has("name")) item.put("name", itemName);
                    String displayName = item.optString("name", itemName);
                    model.addElement(new AttackSurfaceNode(displayName, item));
                }
            }
        }
    }

    private void sendTo(boolean isIntruder) {
        String requestBody = metadataInspector.getText();
        if (requestBody == null || requestBody.isEmpty()) return;

        // Determine a name for the tab
        String primitiveName = "MCP-Request";
        AttackSurfaceNode selected = toolsList.getSelectedValue();
        if (selected == null) selected = resourcesList.getSelectedValue();
        if (selected == null) selected = promptsList.getSelectedValue();
        if (selected != null) {
            primitiveName = "MCP: " + selected.toString();
        }

        // Directly target the internal proxy port
        // This avoids DNS issues and "HttpHandler" redirection complexity
        int port = mcpProxy.getInternalPort();
        if (port <= 0) {
            api.logging().logToError("Internal proxy not ready.");
            return;
        }

        HttpService httpService = HttpService.httpService("127.0.0.1", port, false);
        String rawRequestString = 
            "POST /invoke HTTP/1.1\r\n" +
            "Host: mcp-asd.local\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: " + requestBody.length() + "\r\n" +
            "\r\n" +
            requestBody;

        HttpRequest httpRequest = HttpRequest.httpRequest(
            httpService,
            ByteArray.byteArray(rawRequestString.getBytes(StandardCharsets.UTF_8))
        );
        
        if (isIntruder) {
            api.intruder().sendToIntruder(httpRequest);
        } else {
            api.repeater().sendToRepeater(httpRequest, primitiveName);
        }
        
        api.logging().logToOutput("Sent to " + (isIntruder ? "Intruder" : "Repeater") + " [" + primitiveName + "]: " + requestBody);
    }
    
    // Reuse existing logic, simplified
    private String generatePrototypeRequest(AttackSurfaceNode node, String parentCategory) {
        JSONObject itemData = node.getData();
        String methodName = node.toString();
        
        JSONObject requestJson = new JSONObject();
        requestJson.put("jsonrpc", "2.0");
        requestJson.put("id", java.util.UUID.randomUUID().toString());

        if ("Tools".equals(parentCategory)) {
            requestJson.put("method", "tools/invoke");
            JSONObject params = new JSONObject();
            params.put("name", methodName);
            
            JSONObject inputSchema = itemData.optJSONObject("inputSchema");
            JSONObject arguments = new JSONObject();
            if (inputSchema != null && inputSchema.has("properties")) {
                JSONObject properties = inputSchema.getJSONObject("properties");
                for (String key : properties.keySet()) {
                    arguments.put(key, "<" + properties.getJSONObject(key).optString("type", "string") + ">");
                }
            }
            params.put("arguments", arguments); 
            requestJson.put("params", params);
        } else if ("Resources".equals(parentCategory)) {
            requestJson.put("method", "resources/read");
            requestJson.put("params", new JSONObject().put("uri", itemData.optString("uri", "<uri>")));
        } else if ("Prompts".equals(parentCategory)) {
            requestJson.put("method", "prompts/get");
            requestJson.put("params", new JSONObject().put("name", methodName));
        } else {
            return itemData.toString(4);
        }
        return requestJson.toString(4);
    }

    private void addContextMenu(JList<AttackSurfaceNode> list, String type) {
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem scanItem = new JMenuItem("Active Scan (Phase 2)");
        scanItem.addActionListener(e -> {
            AttackSurfaceNode selected = list.getSelectedValue();
            if (selected != null) {
                if ("Tools".equals(type)) {
                    tester.scanTool(selected);
                } else if ("Resources".equals(type)) {
                    tester.scanResource(selected);
                }
            }
        });
        popupMenu.add(scanItem);

        list.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }
            private void showPopup(MouseEvent e) {
                int index = list.locationToIndex(e.getPoint());
                if (index != -1) {
                    list.setSelectedIndex(index);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }
}