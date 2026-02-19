package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Swing-based UI tab for the Session Share extension.
 * Provides role selection (Leader/Follower) and mode-specific controls.
 */
public class ConfigPanel extends JPanel {

    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private final TokenServer tokenServer;
    private final TokenCaptureHandler captureHandler;
    private final TokenPoller tokenPoller;
    private final TokenInjector tokenInjector;

    // Role selection
    private JRadioButton leaderRadio;
    private JRadioButton followerRadio;

    // Card layout for switching between leader/follower panels
    private JPanel cardPanel;
    private CardLayout cardLayout;

    // Leader controls
    private JTextField leaderPortField;
    private JPasswordField leaderPasswordField;
    private JTextField leaderTargetField;
    private JTextField leaderCsrfHeaderField;
    private JButton leaderStartStopButton;
    private JLabel leaderStatusLabel;
    private JTextArea leaderTokenDisplay;
    private DefaultTableModel leaderCustomHeadersModel;
    private JTable leaderCustomHeadersTable;

    // Follower controls
    private JTextField followerIpField;
    private JTextField followerPortField;
    private JPasswordField followerPasswordField;
    private JTextField followerPollIntervalField;
    private JTextField followerTargetField;
    private JButton followerConnectButton;
    private JLabel followerStatusLabel;
    private JTextArea followerTokenDisplay;

    // Background UI refresh
    private ScheduledExecutorService uiRefresher;

    public ConfigPanel(MontoyaApi api, TokenStore tokenStore,
                       TokenServer tokenServer, TokenCaptureHandler captureHandler,
                       TokenPoller tokenPoller, TokenInjector tokenInjector) {
        this.api = api;
        this.tokenStore = tokenStore;
        this.tokenServer = tokenServer;
        this.captureHandler = captureHandler;
        this.tokenPoller = tokenPoller;
        this.tokenInjector = tokenInjector;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(createRolePanel(), BorderLayout.NORTH);
        add(createCardPanel(), BorderLayout.CENTER);

        startUiRefresh();
    }

    // ==================== Role selection panel ====================

    private JPanel createRolePanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Role",
                TitledBorder.LEFT, TitledBorder.TOP));

        leaderRadio = new JRadioButton("Leader (serves tokens)", true);
        followerRadio = new JRadioButton("Follower (fetches tokens)");

        ButtonGroup group = new ButtonGroup();
        group.add(leaderRadio);
        group.add(followerRadio);

        leaderRadio.addActionListener(e -> switchRole("leader"));
        followerRadio.addActionListener(e -> switchRole("follower"));

        panel.add(leaderRadio);
        panel.add(Box.createHorizontalStrut(20));
        panel.add(followerRadio);

        return panel;
    }

    private void switchRole(String role) {
        cardLayout.show(cardPanel, role);
    }

    // ==================== Card panel (leader/follower) ====================

    private JPanel createCardPanel() {
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);

        cardPanel.add(createLeaderPanel(), "leader");
        cardPanel.add(createFollowerPanel(), "follower");

        return cardPanel;
    }

    // ==================== Leader panel ====================

    private JPanel createLeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // Top section: config fields + custom headers table
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));

        // Configuration fields
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Leader Configuration",
                TitledBorder.LEFT, TitledBorder.TOP));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Port
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Server Port:"), gbc);
        leaderPortField = new JTextField("8888", 8);
        gbc.gridx = 1;
        configPanel.add(leaderPortField, gbc);

        // Password
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Password:"), gbc);
        leaderPasswordField = new JPasswordField(20);
        gbc.gridx = 1;
        configPanel.add(leaderPasswordField, gbc);

        // Target scope
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Target Scope:"), gbc);
        leaderTargetField = new JTextField("example.com", 25);
        leaderTargetField.setToolTipText("Comma-separated domains to capture tokens from");
        gbc.gridx = 1;
        configPanel.add(leaderTargetField, gbc);

        // CSRF header name
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("CSRF Header:"), gbc);
        leaderCsrfHeaderField = new JTextField("X-CSRF-Token", 20);
        leaderCsrfHeaderField.setToolTipText("Name of the CSRF token header (leave empty to disable)");
        gbc.gridx = 1;
        configPanel.add(leaderCsrfHeaderField, gbc);

        // Start/Stop button
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leaderStartStopButton = new JButton("Start Server");
        leaderStartStopButton.addActionListener(e -> toggleLeaderServer());
        buttonPanel.add(leaderStartStopButton);
        buttonPanel.add(Box.createHorizontalStrut(15));
        leaderStatusLabel = new JLabel("Status: Stopped");
        leaderStatusLabel.setForeground(Color.RED);
        buttonPanel.add(leaderStatusLabel);
        configPanel.add(buttonPanel, gbc);
        gbc.gridwidth = 1;

        topPanel.add(configPanel, BorderLayout.CENTER);

        // Custom headers table panel (right side of top)
        topPanel.add(createCustomHeadersPanel(), BorderLayout.EAST);

        panel.add(topPanel, BorderLayout.NORTH);

        // Token display
        JPanel tokenPanel = new JPanel(new BorderLayout());
        tokenPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Current Tokens",
                TitledBorder.LEFT, TitledBorder.TOP));

        leaderTokenDisplay = new JTextArea(12, 50);
        leaderTokenDisplay.setEditable(false);
        leaderTokenDisplay.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        leaderTokenDisplay.setText("(no tokens captured yet)");
        tokenPanel.add(new JScrollPane(leaderTokenDisplay), BorderLayout.CENTER);

        panel.add(tokenPanel, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Creates the custom headers panel with a table and +/- buttons.
     * Each row is a header name the leader should watch for in responses.
     * Values are captured automatically from traffic.
     */
    private JPanel createCustomHeadersPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Custom Headers to Capture",
                TitledBorder.LEFT, TitledBorder.TOP));
        panel.setPreferredSize(new Dimension(300, 0));

        // Table model: single column "Header Name"
        leaderCustomHeadersModel = new DefaultTableModel(new String[]{"Header Name"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };
        leaderCustomHeadersTable = new JTable(leaderCustomHeadersModel);
        leaderCustomHeadersTable.setRowHeight(24);
        leaderCustomHeadersTable.getTableHeader().setReorderingAllowed(false);

        JScrollPane tableScroll = new JScrollPane(leaderCustomHeadersTable);
        tableScroll.setPreferredSize(new Dimension(280, 120));
        panel.add(tableScroll, BorderLayout.CENTER);

        // +/- buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton addBtn = new JButton("+");
        addBtn.setToolTipText("Add a custom header to watch");
        addBtn.setMargin(new Insets(2, 8, 2, 8));
        addBtn.addActionListener(e -> {
            leaderCustomHeadersModel.addRow(new Object[]{""});
            int newRow = leaderCustomHeadersModel.getRowCount() - 1;
            leaderCustomHeadersTable.editCellAt(newRow, 0);
            leaderCustomHeadersTable.requestFocusInWindow();
        });

        JButton removeBtn = new JButton("-");
        removeBtn.setToolTipText("Remove selected header");
        removeBtn.setMargin(new Insets(2, 8, 2, 8));
        removeBtn.addActionListener(e -> {
            int selected = leaderCustomHeadersTable.getSelectedRow();
            if (selected >= 0) {
                // Stop editing before removing
                if (leaderCustomHeadersTable.isEditing()) {
                    leaderCustomHeadersTable.getCellEditor().stopCellEditing();
                }
                leaderCustomHeadersModel.removeRow(selected);
            }
        });

        btnPanel.add(addBtn);
        btnPanel.add(removeBtn);
        btnPanel.add(Box.createHorizontalStrut(8));
        btnPanel.add(new JLabel("<html><i>e.g. X-Api-Key, X-Request-Id</i></html>"));

        panel.add(btnPanel, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Read all header names from the custom headers table.
     */
    private List<String> getCustomHeaderNamesFromTable() {
        // Stop any in-progress cell editing so the value is committed
        if (leaderCustomHeadersTable.isEditing()) {
            leaderCustomHeadersTable.getCellEditor().stopCellEditing();
        }

        List<String> names = new ArrayList<>();
        for (int i = 0; i < leaderCustomHeadersModel.getRowCount(); i++) {
            Object val = leaderCustomHeadersModel.getValueAt(i, 0);
            if (val != null) {
                String name = val.toString().trim();
                if (!name.isEmpty()) {
                    names.add(name);
                }
            }
        }
        return names;
    }

    private void toggleLeaderServer() {
        api.logging().logToOutput("[Leader] toggleLeaderServer() called, isRunning=" + tokenServer.isRunning());

        if (tokenServer.isRunning()) {
            // Stop server
            tokenServer.stop();
            captureHandler.setActive(false);

            leaderStartStopButton.setText("Start Server");
            leaderStatusLabel.setText("Status: Stopped");
            leaderStatusLabel.setForeground(Color.RED);
            setLeaderFieldsEnabled(true);
            api.logging().logToOutput("[Leader] Server stopped.");
        } else {
            // Start server
            try {
                int port = Integer.parseInt(leaderPortField.getText().trim());
                String password = new String(leaderPasswordField.getPassword());
                String target = leaderTargetField.getText().trim();
                String csrfHeader = leaderCsrfHeaderField.getText().trim();

                api.logging().logToOutput("[Leader] Starting server on port " + port
                        + ", target=" + target);

                tokenStore.setTarget(target);
                tokenStore.setCsrfHeaderName(csrfHeader);
                tokenStore.setWatchedHeaders(getCustomHeaderNamesFromTable());
                tokenServer.setPassword(password);

                tokenServer.start(port);
                captureHandler.setActive(true);

                leaderStartStopButton.setText("Stop Server");
                leaderStatusLabel.setText("Status: Running on port " + port);
                leaderStatusLabel.setForeground(new Color(0, 128, 0));
                setLeaderFieldsEnabled(false);
                api.logging().logToOutput("[Leader] Server started successfully on port " + port);
            } catch (NumberFormatException ex) {
                api.logging().logToError("[Leader] Invalid port: " + ex.getMessage());
                leaderStatusLabel.setText("Status: Error — invalid port");
                leaderStatusLabel.setForeground(Color.RED);
            } catch (Throwable ex) {
                // Catch Throwable (not just Exception) to surface NoClassDefFoundError,
                // module access errors, BindException, etc.
                api.logging().logToError("[Leader] Failed to start server: " + ex.getClass().getName()
                        + " — " + ex.getMessage());
                leaderStatusLabel.setText("Status: Error — " + ex.getMessage());
                leaderStatusLabel.setForeground(Color.RED);
            }
        }
    }

    private void setLeaderFieldsEnabled(boolean enabled) {
        leaderPortField.setEnabled(enabled);
        leaderPasswordField.setEnabled(enabled);
        leaderTargetField.setEnabled(enabled);
        leaderCsrfHeaderField.setEnabled(enabled);
        leaderCustomHeadersTable.setEnabled(enabled);
    }

    // ==================== Follower panel ====================

    private JPanel createFollowerPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // Configuration section
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Follower Configuration",
                TitledBorder.LEFT, TitledBorder.TOP));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Leader IP
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Leader IP:"), gbc);
        followerIpField = new JTextField("192.168.1.100", 15);
        gbc.gridx = 1;
        configPanel.add(followerIpField, gbc);

        // Leader Port
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Leader Port:"), gbc);
        followerPortField = new JTextField("8888", 8);
        gbc.gridx = 1;
        configPanel.add(followerPortField, gbc);

        // Password
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Password:"), gbc);
        followerPasswordField = new JPasswordField(20);
        gbc.gridx = 1;
        configPanel.add(followerPasswordField, gbc);

        // Poll interval
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Poll Interval (s):"), gbc);
        followerPollIntervalField = new JTextField("5", 5);
        gbc.gridx = 1;
        configPanel.add(followerPollIntervalField, gbc);

        // Target scope
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Target Scope:"), gbc);
        followerTargetField = new JTextField("example.com", 25);
        followerTargetField.setToolTipText("Comma-separated domains to inject tokens into");
        gbc.gridx = 1;
        configPanel.add(followerTargetField, gbc);

        // Connect/Disconnect button
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        followerConnectButton = new JButton("Connect");
        followerConnectButton.addActionListener(e -> toggleFollowerConnection());
        buttonPanel.add(followerConnectButton);
        buttonPanel.add(Box.createHorizontalStrut(15));
        followerStatusLabel = new JLabel("Status: Disconnected");
        followerStatusLabel.setForeground(Color.RED);
        buttonPanel.add(followerStatusLabel);
        configPanel.add(buttonPanel, gbc);
        gbc.gridwidth = 1;

        panel.add(configPanel, BorderLayout.NORTH);

        // Token display
        JPanel tokenPanel = new JPanel(new BorderLayout());
        tokenPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Fetched Tokens",
                TitledBorder.LEFT, TitledBorder.TOP));

        followerTokenDisplay = new JTextArea(12, 50);
        followerTokenDisplay.setEditable(false);
        followerTokenDisplay.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        followerTokenDisplay.setText("(not connected)");
        tokenPanel.add(new JScrollPane(followerTokenDisplay), BorderLayout.CENTER);

        panel.add(tokenPanel, BorderLayout.CENTER);

        return panel;
    }

    private void toggleFollowerConnection() {
        api.logging().logToOutput("[Follower] toggleFollowerConnection() called, isConnected=" + tokenPoller.isConnected());

        if (tokenPoller.isConnected()) {
            // Disconnect
            tokenPoller.stop();
            tokenInjector.setActive(false);

            followerConnectButton.setText("Connect");
            followerStatusLabel.setText("Status: Disconnected");
            followerStatusLabel.setForeground(Color.RED);
            setFollowerFieldsEnabled(true);
            api.logging().logToOutput("[Follower] Disconnected.");
        } else {
            // Connect
            try {
                String ip = followerIpField.getText().trim();
                int port = Integer.parseInt(followerPortField.getText().trim());
                String password = new String(followerPasswordField.getPassword());
                int interval = Integer.parseInt(followerPollIntervalField.getText().trim());
                String target = followerTargetField.getText().trim();

                api.logging().logToOutput("[Follower] Connecting to " + ip + ":" + port);

                tokenStore.setTarget(target);
                tokenPoller.setLeaderIp(ip);
                tokenPoller.setLeaderPort(port);
                tokenPoller.setPassword(password);
                tokenPoller.setPollIntervalSeconds(interval);

                tokenPoller.start();
                tokenInjector.setActive(true);

                followerConnectButton.setText("Disconnect");
                followerStatusLabel.setText("Status: Connected to " + ip + ":" + port);
                followerStatusLabel.setForeground(new Color(0, 128, 0));
                setFollowerFieldsEnabled(false);
                api.logging().logToOutput("[Follower] Connected to " + ip + ":" + port);
            } catch (NumberFormatException ex) {
                api.logging().logToError("[Follower] Invalid port/interval: " + ex.getMessage());
                followerStatusLabel.setText("Status: Error — invalid port or interval");
                followerStatusLabel.setForeground(Color.RED);
            } catch (Throwable ex) {
                api.logging().logToError("[Follower] Failed to connect: " + ex.getClass().getName()
                        + " — " + ex.getMessage());
                followerStatusLabel.setText("Status: Error — " + ex.getMessage());
                followerStatusLabel.setForeground(Color.RED);
            }
        }
    }

    private void setFollowerFieldsEnabled(boolean enabled) {
        followerIpField.setEnabled(enabled);
        followerPortField.setEnabled(enabled);
        followerPasswordField.setEnabled(enabled);
        followerPollIntervalField.setEnabled(enabled);
        followerTargetField.setEnabled(enabled);
    }

    // ==================== Periodic UI refresh ====================

    /**
     * Refreshes the token display areas every 2 seconds on the EDT.
     */
    private void startUiRefresh() {
        uiRefresher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionShare-UIRefresh");
            t.setDaemon(true);
            return t;
        });

        uiRefresher.scheduleAtFixedRate(() -> {
            SwingUtilities.invokeLater(() -> {
                try {
                    // Update leader token display
                    if (tokenServer.isRunning()) {
                        leaderTokenDisplay.setText(tokenStore.toDisplayString()
                                + "\nRequests served: " + tokenServer.getRequestCount());
                    }

                    // Update leader status
                    if (tokenServer.isRunning()) {
                        leaderStatusLabel.setText("Status: Running | Requests: "
                                + tokenServer.getRequestCount());
                    }

                    // Update follower token display
                    if (tokenPoller.isConnected()) {
                        String display = tokenStore.toDisplayString();
                        if (tokenPoller.getLastFetchTime() != null) {
                            display += "\nLast fetch: " + tokenPoller.getLastFetchTime();
                        }
                        String error = tokenPoller.getLastError();
                        if (!error.isEmpty()) {
                            display += "\nLast error: " + error;
                        }
                        followerTokenDisplay.setText(display);
                    }

                    // Update follower status
                    if (tokenPoller.isConnected()) {
                        String status = "Status: Connected";
                        if (tokenPoller.getLastFetchTime() != null) {
                            status += " | Last fetch: " + tokenPoller.getLastFetchTime();
                        }
                        String error = tokenPoller.getLastError();
                        if (!error.isEmpty()) {
                            status = "Status: Error — " + error;
                            followerStatusLabel.setForeground(Color.ORANGE);
                        } else {
                            followerStatusLabel.setForeground(new Color(0, 128, 0));
                        }
                        followerStatusLabel.setText(status);
                    }
                } catch (Exception e) {
                    // Silently handle UI refresh errors
                }
            });
        }, 2, 2, TimeUnit.SECONDS);
    }

    /**
     * Stop the UI refresh timer. Called during extension unload.
     */
    public void stopUiRefresh() {
        if (uiRefresher != null) {
            uiRefresher.shutdownNow();
        }
    }
}
