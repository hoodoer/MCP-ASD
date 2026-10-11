package com.mcp_asd.burp.ui;

import burp.api.montoya.ui.settings.SettingsPanel;
import com.mcp_asd.burp.GlobalSettings;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.Set;

/**
 * MCP-ASD settings, embedded in Burp's Settings window (Settings > Extensions > MCP-ASD).
 * Changes are written straight to Burp's preferences, as Burp's own settings are.
 */
public class McpSettingsPanel implements SettingsPanel {
    private final GlobalSettings settings;
    private final JPanel panel;

    private JCheckBox proxyTrafficCheckbox;
    private JTextField proxyHostField;
    private JTextField proxyPortField;
    private JCheckBox ignoreTlsErrorsCheckbox;
    private JCheckBox passiveChecksCheckbox;

    public McpSettingsPanel(GlobalSettings settings) {
        this.settings = settings;
        this.panel = buildPanel();
        loadSettings();
        wireListeners();
    }

    @Override
    public JComponent uiComponent() {
        return panel;
    }

    @Override
    public Set<String> keywords() {
        return Set.of("MCP", "MCP-ASD", "Model Context Protocol", "proxy", "TLS", "passive");
    }

    private JPanel buildPanel() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Group 1: Internal Traffic Proxying
        JPanel proxyPanel = new JPanel(new GridBagLayout());
        proxyPanel.setBorder(BorderFactory.createTitledBorder("Internal Traffic Visibility (SSE / WebSocket)"));
        GridBagConstraints gbc = newConstraints();

        proxyTrafficCheckbox = new JCheckBox("Proxy Handshake/Enumeration Traffic");
        proxyPanel.add(proxyTrafficCheckbox, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(0, 25, 5, 5);
        proxyPanel.add(description("Route internal SSE/WebSocket traffic through Burp's Proxy listener so the handshake and "
                + "enumeration requests appear in Logger and Proxy History. HTTP (POST only) and endpoint auto-detection "
                + "always use Burp's HTTP stack and appear in Logger."), gbc);

        gbc.gridy++;
        JPanel proxyConfig = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        proxyConfig.add(new JLabel("Proxy Host:"));
        proxyHostField = new JTextField(10);
        proxyConfig.add(proxyHostField);
        proxyConfig.add(new JLabel("Port:"));
        proxyPortField = new JTextField(5);
        proxyConfig.add(proxyPortField);
        proxyPanel.add(proxyConfig, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(8, 2, 2, 2);
        ignoreTlsErrorsCheckbox = new JCheckBox("Ignore TLS certificate errors on direct connections");
        proxyPanel.add(ignoreTlsErrorsCheckbox, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(0, 25, 5, 5);
        proxyPanel.add(description("Only applies when the option above is off. Proxied traffic trusts Burp's CA, and Burp "
                + "applies its own upstream TLS settings."), gbc);

        // Group 2: Detection
        JPanel detectionPanel = new JPanel(new GridBagLayout());
        detectionPanel.setBorder(BorderFactory.createTitledBorder("MCP Server Detection (Burp Scanner)"));
        gbc = newConstraints();

        passiveChecksCheckbox = new JCheckBox("Passive Checks for MCP Server");
        detectionPanel.add(passiveChecksCheckbox, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(0, 25, 5, 5);
        detectionPanel.add(description("Monitor traffic headers and bodies for MCP indicators (e.g., 'MCP-Protocol-Version', "
                + "'mcp-session-id') during passive scanning. Active probing of common MCP endpoints runs as part of "
                + "Burp's active scans. Requires Burp Suite Professional."), gbc);

        mainPanel.add(proxyPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(detectionPanel);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(mainPanel, BorderLayout.NORTH);
        return wrapper;
    }

    private static GridBagConstraints newConstraints() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 2, 2, 2);
        return gbc;
    }

    private static JTextArea description(String text) {
        JTextArea area = new JTextArea(text);
        area.setWrapStyleWord(true);
        area.setLineWrap(true);
        area.setEditable(false);
        area.setOpaque(false);
        area.setFont(area.getFont().deriveFont(11f));
        return area;
    }

    private void loadSettings() {
        proxyTrafficCheckbox.setSelected(settings.isProxyTrafficEnabled());
        proxyHostField.setText(settings.getProxyHost());
        proxyPortField.setText(String.valueOf(settings.getProxyPort()));
        ignoreTlsErrorsCheckbox.setSelected(settings.isIgnoreTlsErrorsEnabled());
        passiveChecksCheckbox.setSelected(settings.isPassiveChecksEnabled());
        updateEnabledState();
    }

    private void wireListeners() {
        proxyTrafficCheckbox.addActionListener(e -> {
            settings.setProxyTrafficEnabled(proxyTrafficCheckbox.isSelected());
            updateEnabledState();
        });
        ignoreTlsErrorsCheckbox.addActionListener(e -> settings.setIgnoreTlsErrorsEnabled(ignoreTlsErrorsCheckbox.isSelected()));
        passiveChecksCheckbox.addActionListener(e -> settings.setPassiveChecksEnabled(passiveChecksCheckbox.isSelected()));

        onTextChange(proxyHostField, () -> {
            String host = proxyHostField.getText().trim();
            if (!host.isEmpty()) settings.setProxyHost(host);
        });
        onTextChange(proxyPortField, () -> {
            try {
                int port = Integer.parseInt(proxyPortField.getText().trim());
                if (port >= 1 && port <= 65535) settings.setProxyPort(port);
            } catch (NumberFormatException ignored) {
                // Keep the last valid port until the field holds a valid number
            }
        });
    }

    private void updateEnabledState() {
        boolean proxied = proxyTrafficCheckbox.isSelected();
        proxyHostField.setEnabled(proxied);
        proxyPortField.setEnabled(proxied);
        ignoreTlsErrorsCheckbox.setEnabled(!proxied);
    }

    private static void onTextChange(JTextField field, Runnable action) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { action.run(); }
            @Override public void removeUpdate(DocumentEvent e) { action.run(); }
            @Override public void changedUpdate(DocumentEvent e) { action.run(); }
        });
    }
}
