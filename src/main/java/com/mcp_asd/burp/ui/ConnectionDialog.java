package com.mcp_asd.burp.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class ConnectionDialog extends JDialog {
    private JTextField hostField;
    private JTextField portField;
    private JComboBox<String> transportCombo;
    private JTextField pathField;
    
    // Auth Components
    private DefaultTableModel headersModel;
    private JTable headersTable;
    private JCheckBox mtlsCheckBox;
    private JTextField certPathField;
    private JPasswordField certPasswordField;
    private JButton browseCertButton;

    private boolean confirmed = false;
    private ConnectionConfiguration configuration;

    public ConnectionDialog(Frame owner, String defaultHost, int defaultPort, ConnectionConfiguration existingConfig) {
        super(owner, "Connect to MCP Server", true);
        setLayout(new BorderLayout());
        
        // Use existing config if available, otherwise defaults
        String initialHost = (existingConfig != null) ? existingConfig.getHost() : defaultHost;
        int initialPort = (existingConfig != null) ? existingConfig.getPort() : defaultPort;
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // --- Tab 1: General Connection ---
        JPanel generalTab = createGeneralTab(initialHost, initialPort);
        tabbedPane.addTab("General", generalTab);
        
        // --- Tab 2: Authentication ---
        JPanel authTab = createAuthTab();
        tabbedPane.addTab("Authentication", authTab);

        // Pre-fill fields if config exists
        if (existingConfig != null) {
            transportCombo.setSelectedItem(existingConfig.getTransport());
            pathField.setText(existingConfig.getPath());
            
            // Fill Headers
            for (Map.Entry<String, String> entry : existingConfig.getHeaders().entrySet()) {
                headersModel.addRow(new String[]{entry.getKey(), entry.getValue()});
            }
            
            // Fill mTLS
            if (existingConfig.isUseMtls()) {
                mtlsCheckBox.setSelected(true);
                toggleMtlsFields(true);
                certPathField.setText(existingConfig.getClientCertPath());
                certPasswordField.setText(existingConfig.getClientCertPassword());
            }
        }

        add(tabbedPane, BorderLayout.CENTER);

        // --- Buttons ---
        JPanel buttonPanel = new JPanel();
        JButton connectButton = new JButton("Connect");
        connectButton.setPreferredSize(new Dimension(100, 30));
        connectButton.addActionListener(e -> onConnect());
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setPreferredSize(new Dimension(100, 30));
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(connectButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        setMinimumSize(new Dimension(500, 400));
        pack();
        setLocationRelativeTo(owner);
    }

    private JPanel createGeneralTab(String defaultHost, int defaultPort) {
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Row 0: Host
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        formPanel.add(new JLabel("Host:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        hostField = new JTextField(defaultHost);
        formPanel.add(hostField, gbc);

        // Row 1: Port
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        formPanel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        portField = new JTextField(String.valueOf(defaultPort));
        formPanel.add(portField, gbc);

        // Row 2: Auto-Detect
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JButton detectButton = new JButton("Auto-Detect Endpoints");
        formPanel.add(detectButton, gbc);
        
        detectButton.addActionListener(e -> {
            detectButton.setEnabled(false);
            detectButton.setText("Scanning...");
            AutoDetector.detect(hostField.getText(), getPort()).thenAccept(results -> {
                SwingUtilities.invokeLater(() -> {
                    detectButton.setEnabled(true);
                    detectButton.setText("Auto-Detect Endpoints");
                    if (!results.isEmpty()) {
                        if (results.size() == 1) {
                            AutoDetector.DetectionResult res = results.get(0);
                            transportCombo.setSelectedItem(res.transport);
                            pathField.setText(res.path);
                            JOptionPane.showMessageDialog(this, "Found " + res.transport + " endpoint at " + res.path, "Detection Successful", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            AutoDetector.DetectionResult selected = (AutoDetector.DetectionResult) JOptionPane.showInputDialog(
                                this, 
                                "Multiple MCP endpoints were detected on this server.\nPlease select the one you want to use:",
                                "Select Endpoint",
                                JOptionPane.QUESTION_MESSAGE,
                                null,
                                results.toArray(),
                                results.get(0)
                            );
                            if (selected != null) {
                                transportCombo.setSelectedItem(selected.transport);
                                pathField.setText(selected.path);
                            }
                        }
                    } else {
                        JOptionPane.showMessageDialog(this, "No common MCP endpoint found.", "Detection Failed", JOptionPane.WARNING_MESSAGE);
                    }
                });
            });
        });

        // Row 3: Transport
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1; gbc.weightx = 0.0;
        formPanel.add(new JLabel("Transport:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0;
        transportCombo = new JComboBox<>(new String[]{"SSE", "WebSocket"});
        transportCombo.addActionListener(e -> {
            if ("WebSocket".equals(transportCombo.getSelectedItem())) {
                if (pathField.getText().equals("/mcp")) pathField.setText("/ws");
            } else {
                if (pathField.getText().equals("/ws")) pathField.setText("/mcp");
            }
        });
        formPanel.add(transportCombo, gbc);

        // Row 4: Path
        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0.0;
        formPanel.add(new JLabel("Path:"), gbc);
        gbc.gridx = 1; gbc.gridy = 4; gbc.weightx = 1.0;
        pathField = new JTextField("/mcp");
        formPanel.add(pathField, gbc);

        return formPanel;
    }

    private JPanel createAuthTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- Info Notice ---
        JTextArea infoNotice = new JTextArea(
            "NOTE: MCP-ASD manages these credentials internally. Custom headers and mTLS certificates " +
            "are injected into the real transport connection automatically. You will NOT see them " +
            "in Repeater or Intruder requests."
        );
        infoNotice.setLineWrap(true);
        infoNotice.setWrapStyleWord(true);
        infoNotice.setEditable(false);
        infoNotice.setBackground(panel.getBackground());
        infoNotice.setFont(infoNotice.getFont().deriveFont(Font.ITALIC));
        infoNotice.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        panel.add(infoNotice, BorderLayout.NORTH);

        // --- Headers Section ---
        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.setBorder(BorderFactory.createTitledBorder("HTTP Headers (OAuth/API Keys)"));
        
        headersModel = new DefaultTableModel(new String[]{"Key", "Value"}, 0);
        headersTable = new JTable(headersModel);
        headersPanel.add(new JScrollPane(headersTable), BorderLayout.CENTER);
        
        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addHeaderBtn = new JButton("Add Header");
        addHeaderBtn.addActionListener(e -> headersModel.addRow(new String[]{"", ""}));
        
        JButton addBearerBtn = new JButton("Add Bearer Token");
        addBearerBtn.addActionListener(e -> headersModel.addRow(new String[]{"Authorization", "Bearer <token>"}));
        
        JButton removeHeaderBtn = new JButton("Remove");
        removeHeaderBtn.addActionListener(e -> {
            int row = headersTable.getSelectedRow();
            if (row >= 0) headersModel.removeRow(row);
        });
        
        headerButtons.add(addHeaderBtn);
        headerButtons.add(addBearerBtn);
        headerButtons.add(removeHeaderBtn);
        headersPanel.add(headerButtons, BorderLayout.SOUTH);
        
        panel.add(headersPanel, BorderLayout.CENTER);

        // --- mTLS Section ---
        JPanel mtlsPanel = new JPanel(new GridBagLayout());
        mtlsPanel.setBorder(BorderFactory.createTitledBorder("mTLS (Client Certificate)"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        mtlsCheckBox = new JCheckBox("Enable mTLS");
        mtlsCheckBox.addActionListener(e -> toggleMtlsFields(mtlsCheckBox.isSelected()));
        mtlsPanel.add(mtlsCheckBox, gbc);
        
        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        mtlsPanel.add(new JLabel("PKCS#12 File (.p12):"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        certPathField = new JTextField();
        mtlsPanel.add(certPathField, gbc);
        
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.0;
        browseCertButton = new JButton("Browse...");
        browseCertButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                certPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        mtlsPanel.add(browseCertButton, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        mtlsPanel.add(new JLabel("Password:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
        certPasswordField = new JPasswordField();
        mtlsPanel.add(certPasswordField, gbc);
        
        toggleMtlsFields(false); // Init disabled
        
        panel.add(mtlsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void toggleMtlsFields(boolean enabled) {
        certPathField.setEnabled(enabled);
        certPasswordField.setEnabled(enabled);
        browseCertButton.setEnabled(enabled);
    }

    private void onConnect() {
        configuration = new ConnectionConfiguration(
            hostField.getText(), 
            getPort(), 
            (String)transportCombo.getSelectedItem(), 
            pathField.getText()
        );
        
        // Parse Headers
        Map<String, String> headers = new HashMap<>();
        for (int i = 0; i < headersModel.getRowCount(); i++) {
            String key = (String) headersModel.getValueAt(i, 0);
            String val = (String) headersModel.getValueAt(i, 1);
            if (key != null && !key.trim().isEmpty()) {
                headers.put(key.trim(), val != null ? val.trim() : "");
            }
        }
        configuration.setHeaders(headers);
        
        // Parse mTLS
        if (mtlsCheckBox.isSelected()) {
            configuration.setUseMtls(true);
            configuration.setClientCertPath(certPathField.getText());
            configuration.setClientCertPassword(new String(certPasswordField.getPassword()));
        }
        
        confirmed = true;
        dispose();
    }

    private int getPort() {
        try {
            return Integer.parseInt(portField.getText());
        } catch (NumberFormatException e) {
            return 80;
        }
    }

    public boolean isConfirmed() { return confirmed; }
    public ConnectionConfiguration getConfiguration() { return configuration; }
}