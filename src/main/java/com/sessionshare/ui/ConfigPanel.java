package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.session.SessionManager;

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
 * Provides role selection (Leader/Follower) and mode-specific controls,
 * plus an always-visible Session Manager panel for auto-refresh.
 */
public class ConfigPanel extends JPanel {

    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private final TokenServer tokenServer;
    private final TokenCaptureHandler captureHandler;
    private final TokenPoller tokenPoller;
    private final TokenInjector tokenInjector;
    private final SessionManager sessionManager;

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

    // Session Manager controls
    private JCheckBox smEnabledCheckbox;
    private JTextField smLoginUrlField;
    private JComboBox<String> smMethodCombo;
    private JTextField smContentTypeField;
    private JTextArea smBodyArea;
    private JTextArea smExtraHeadersArea;
    private JTextField smBufferField;
    private JButton smTestButton;
    private JButton smRefreshNowButton;
    private JLabel smStatusLabel;
    private JLabel smJwtExpiryLabel;
    private JLabel smRefreshCountLabel;

    // Background UI refresh
    private ScheduledExecutorService uiRefresher;

    public ConfigPanel(MontoyaApi api, TokenStore tokenStore,
                       TokenServer tokenServer, TokenCaptureHandler captureHandler,
                       TokenPoller tokenPoller, TokenInjector tokenInjector,
                       SessionManager sessionManager) {
        this.api = api;
        this.tokenStore = tokenStore;
        this.tokenServer = tokenServer;
        this.captureHandler = captureHandler;
        this.tokenPoller = tokenPoller;
        this.tokenInjector = tokenInjector;
        this.sessionManager = sessionManager;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top: Role panel + Leader/Follower cards
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));
        topPanel.add(createRolePanel(), BorderLayout.NORTH);
        topPanel.add(createCardPanel(), BorderLayout.CENTER);

        // Bottom: Session Manager (always visible)
        JPanel sessionManagerPanel = createSessionManagerPanel();

        // Split vertically: top = role/cards, bottom = session manager
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                topPanel, sessionManagerPanel);
        splitPane.setResizeWeight(0.55);
        splitPane.setOneTouchExpandable(true);
        splitPane.setDividerSize(8);

        add(splitPane, BorderLayout.CENTER);

        startUiRefresh();
    }

    // ==================== Role selection panel ====================

    private JPanel createRolePanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Role (Token Sharing)",
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

        leaderTokenDisplay = new JTextArea(8, 50);
        leaderTokenDisplay.setEditable(false);
        leaderTokenDisplay.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        leaderTokenDisplay.setText("(no tokens captured yet)");
        tokenPanel.add(new JScrollPane(leaderTokenDisplay), BorderLayout.CENTER);

        panel.add(tokenPanel, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Creates the custom headers panel with a table and +/- buttons.
     */
    private JPanel createCustomHeadersPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Custom Headers to Capture",
                TitledBorder.LEFT, TitledBorder.TOP));
        panel.setPreferredSize(new Dimension(300, 0));

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

    private List<String> getCustomHeaderNamesFromTable() {
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
            tokenServer.stop();
            captureHandler.setActive(false);

            leaderStartStopButton.setText("Start Server");
            leaderStatusLabel.setText("Status: Stopped");
            leaderStatusLabel.setForeground(Color.RED);
            setLeaderFieldsEnabled(true);
            api.logging().logToOutput("[Leader] Server stopped.");
        } else {
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

        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Follower Configuration",
                TitledBorder.LEFT, TitledBorder.TOP));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Leader IP:"), gbc);
        followerIpField = new JTextField("192.168.1.100", 15);
        gbc.gridx = 1;
        configPanel.add(followerIpField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Leader Port:"), gbc);
        followerPortField = new JTextField("8888", 8);
        gbc.gridx = 1;
        configPanel.add(followerPortField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Password:"), gbc);
        followerPasswordField = new JPasswordField(20);
        gbc.gridx = 1;
        configPanel.add(followerPasswordField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Poll Interval (s):"), gbc);
        followerPollIntervalField = new JTextField("5", 5);
        gbc.gridx = 1;
        configPanel.add(followerPollIntervalField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Target Scope:"), gbc);
        followerTargetField = new JTextField("example.com", 25);
        followerTargetField.setToolTipText("Comma-separated domains to inject tokens into");
        gbc.gridx = 1;
        configPanel.add(followerTargetField, gbc);

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

        JPanel tokenPanel = new JPanel(new BorderLayout());
        tokenPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Fetched Tokens",
                TitledBorder.LEFT, TitledBorder.TOP));

        followerTokenDisplay = new JTextArea(8, 50);
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
            tokenPoller.stop();
            tokenInjector.setActive(false);

            followerConnectButton.setText("Connect");
            followerStatusLabel.setText("Status: Disconnected");
            followerStatusLabel.setForeground(Color.RED);
            setFollowerFieldsEnabled(true);
            api.logging().logToOutput("[Follower] Disconnected.");
        } else {
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

    // ==================== Session Manager panel (always visible) ====================

    /**
     * Creates the Session Manager panel — always visible at the bottom of the tab.
     * This feature works independently of Leader/Follower mode.
     *
     * Provides:
     *   - Login macro configuration (URL, method, body, headers)
     *   - Enable/Disable toggle
     *   - JWT expiry buffer setting
     *   - Test and Refresh Now buttons
     *   - Live status display (JWT expiry countdown, refresh count)
     */
    private JPanel createSessionManagerPanel() {
        JPanel outerPanel = new JPanel(new BorderLayout(8, 8));
        outerPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Session Manager — Auto-Refresh (works without Leader/Follower)",
                TitledBorder.LEFT, TitledBorder.TOP));

        // ---- Left side: Login macro config ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Enable checkbox + buffer seconds on same line
        gbc.gridx = 0; gbc.gridy = row;
        smEnabledCheckbox = new JCheckBox("Enable Session Manager");
        smEnabledCheckbox.setToolTipText("When enabled: auto-checks JWT expiry before requests, refreshes on 401/403, and injects tokens");
        smEnabledCheckbox.addActionListener(e -> toggleSessionManager());
        configPanel.add(smEnabledCheckbox, gbc);

        gbc.gridx = 1;
        JPanel bufferPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        bufferPanel.add(new JLabel("Refresh"));
        smBufferField = new JTextField("30", 4);
        smBufferField.setToolTipText("Refresh the session this many seconds before the JWT expires");
        bufferPanel.add(smBufferField);
        bufferPanel.add(new JLabel("sec before expiry"));
        configPanel.add(bufferPanel, gbc);

        // Login URL
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Login URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        smLoginUrlField = new JTextField(40);
        smLoginUrlField.setToolTipText("Full URL of the login endpoint (e.g. https://target.com/api/login)");
        configPanel.add(smLoginUrlField, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;

        // Method + Content-Type on same line
        row++;
        gbc.gridx = 0; gbc.gridy = row;
        configPanel.add(new JLabel("Method:"), gbc);
        gbc.gridx = 1;
        JPanel methodCtPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        smMethodCombo = new JComboBox<>(new String[]{"POST", "GET", "PUT"});
        smMethodCombo.setToolTipText("HTTP method for the login request");
        methodCtPanel.add(smMethodCombo);
        methodCtPanel.add(Box.createHorizontalStrut(12));
        methodCtPanel.add(new JLabel("Content-Type:"));
        smContentTypeField = new JTextField("application/x-www-form-urlencoded", 25);
        smContentTypeField.setToolTipText("Content-Type header for POST/PUT requests");
        methodCtPanel.add(smContentTypeField);
        configPanel.add(methodCtPanel, gbc);

        // Request body
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.anchor = GridBagConstraints.NORTHWEST;
        configPanel.add(new JLabel("Body:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.4;
        smBodyArea = new JTextArea(3, 40);
        smBodyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        smBodyArea.setToolTipText("Request body (e.g. username=admin&password=pass or JSON)");
        smBodyArea.setLineWrap(true);
        smBodyArea.setWrapStyleWord(true);
        configPanel.add(new JScrollPane(smBodyArea), gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0; gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.WEST;

        // Extra headers
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.anchor = GridBagConstraints.NORTHWEST;
        configPanel.add(new JLabel("<html>Extra<br>Headers:</html>"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.3;
        smExtraHeadersArea = new JTextArea(2, 40);
        smExtraHeadersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        smExtraHeadersArea.setToolTipText("One header per line: Name: Value (e.g. X-Custom: abc)");
        smExtraHeadersArea.setLineWrap(true);
        smExtraHeadersArea.setWrapStyleWord(true);
        configPanel.add(new JScrollPane(smExtraHeadersArea), gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0; gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.WEST;

        // Buttons + status
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        JPanel buttonStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        smTestButton = new JButton("Test Login Macro");
        smTestButton.setToolTipText("Send the login request once and show the result (doesn't need Session Manager to be enabled)");
        smTestButton.addActionListener(e -> testLoginMacro());
        buttonStatusPanel.add(smTestButton);

        smRefreshNowButton = new JButton("Refresh Now");
        smRefreshNowButton.setToolTipText("Force an immediate session refresh using the login macro");
        smRefreshNowButton.addActionListener(e -> forceRefresh());
        buttonStatusPanel.add(smRefreshNowButton);

        buttonStatusPanel.add(Box.createHorizontalStrut(12));

        smStatusLabel = new JLabel("Status: Disabled");
        smStatusLabel.setForeground(Color.GRAY);
        buttonStatusPanel.add(smStatusLabel);

        configPanel.add(buttonStatusPanel, gbc);

        // JWT expiry + refresh count line
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        smJwtExpiryLabel = new JLabel("JWT: No JWT stored");
        smJwtExpiryLabel.setFont(smJwtExpiryLabel.getFont().deriveFont(Font.ITALIC));
        infoPanel.add(smJwtExpiryLabel);

        infoPanel.add(new JLabel("|"));

        smRefreshCountLabel = new JLabel("Refreshes: 0");
        infoPanel.add(smRefreshCountLabel);

        infoPanel.add(new JLabel("|"));

        JLabel helpLabel = new JLabel("<html><i>Tip: Set Target Scope in Leader/Follower config first</i></html>");
        helpLabel.setForeground(Color.GRAY);
        infoPanel.add(helpLabel);

        configPanel.add(infoPanel, gbc);

        outerPanel.add(configPanel, BorderLayout.CENTER);

        return outerPanel;
    }

    /**
     * Toggle the Session Manager on/off.
     * Reads config from UI fields and applies to the SessionManager.
     */
    private void toggleSessionManager() {
        boolean enable = smEnabledCheckbox.isSelected();

        if (enable) {
            // Read config from UI
            String loginUrl = smLoginUrlField.getText().trim();
            if (loginUrl.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Please enter a Login URL before enabling the Session Manager.",
                        "Session Manager", JOptionPane.WARNING_MESSAGE);
                smEnabledCheckbox.setSelected(false);
                return;
            }

            // Also need target scope
            String target = tokenStore.getTarget();
            if (target == null || target.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Please set the Target Scope (in Leader or Follower config above)\n"
                                + "before enabling the Session Manager.\n\n"
                                + "The Session Manager needs to know which domains to manage.",
                        "Session Manager", JOptionPane.WARNING_MESSAGE);
                smEnabledCheckbox.setSelected(false);
                return;
            }

            applySessionManagerConfig();
            sessionManager.setEnabled(true);

            smStatusLabel.setText("Status: Enabled");
            smStatusLabel.setForeground(new Color(0, 128, 0));
            setSessionManagerFieldsEnabled(false);
            api.logging().logToOutput("[SessionManager] Enabled. URL: " + loginUrl);
        } else {
            sessionManager.setEnabled(false);

            smStatusLabel.setText("Status: Disabled");
            smStatusLabel.setForeground(Color.GRAY);
            setSessionManagerFieldsEnabled(true);
            api.logging().logToOutput("[SessionManager] Disabled.");
        }
    }

    /**
     * Apply current UI field values to the SessionManager config.
     */
    private void applySessionManagerConfig() {
        sessionManager.setLoginUrl(smLoginUrlField.getText().trim());
        sessionManager.setLoginMethod((String) smMethodCombo.getSelectedItem());
        sessionManager.setLoginContentType(smContentTypeField.getText().trim());
        sessionManager.setLoginBody(smBodyArea.getText());
        sessionManager.setLoginExtraHeaders(smExtraHeadersArea.getText());

        try {
            int buffer = Integer.parseInt(smBufferField.getText().trim());
            sessionManager.setExpiryBufferSeconds(buffer);
        } catch (NumberFormatException ex) {
            sessionManager.setExpiryBufferSeconds(30);
        }
    }

    /**
     * Test the login macro without enabling the Session Manager.
     * Sends the login request and shows the result in a dialog.
     */
    private void testLoginMacro() {
        String loginUrl = smLoginUrlField.getText().trim();
        if (loginUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a Login URL first.",
                    "Test Login Macro", JOptionPane.WARNING_MESSAGE);
            return;
        }

        smTestButton.setEnabled(false);
        smTestButton.setText("Testing...");

        // Run on background thread to avoid blocking EDT
        Thread.ofVirtual().start(() -> {
            try {
                // Temporarily apply config for testing
                applySessionManagerConfig();
                boolean wasEnabled = sessionManager.isEnabled();
                sessionManager.setEnabled(true);
                boolean success = sessionManager.refreshSession();
                sessionManager.setEnabled(wasEnabled);

                String status = sessionManager.getLastRefreshStatus();

                SwingUtilities.invokeLater(() -> {
                    smTestButton.setEnabled(true);
                    smTestButton.setText("Test Login Macro");

                    if (success) {
                        JOptionPane.showMessageDialog(this,
                                "Login macro succeeded!\n\n" + status
                                        + "\n\nTokens have been updated. Check the token display above.",
                                "Test Login Macro", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(this,
                                "Login macro failed.\n\n" + status
                                        + "\n\nCheck the login URL, method, body, and credentials.",
                                "Test Login Macro", JOptionPane.ERROR_MESSAGE);
                    }
                });
            } catch (Throwable ex) {
                SwingUtilities.invokeLater(() -> {
                    smTestButton.setEnabled(true);
                    smTestButton.setText("Test Login Macro");
                    JOptionPane.showMessageDialog(this,
                            "Error: " + ex.getMessage(),
                            "Test Login Macro", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }

    /**
     * Force an immediate session refresh.
     */
    private void forceRefresh() {
        if (!sessionManager.isEnabled()) {
            JOptionPane.showMessageDialog(this,
                    "Enable the Session Manager first.",
                    "Refresh Now", JOptionPane.WARNING_MESSAGE);
            return;
        }

        smRefreshNowButton.setEnabled(false);
        smRefreshNowButton.setText("Refreshing...");

        Thread.ofVirtual().start(() -> {
            boolean success = sessionManager.refreshSession();
            SwingUtilities.invokeLater(() -> {
                smRefreshNowButton.setEnabled(true);
                smRefreshNowButton.setText("Refresh Now");

                String msg = success ? "Session refreshed successfully!" : "Refresh failed: " + sessionManager.getLastRefreshStatus();
                smStatusLabel.setText("Status: " + sessionManager.getLastRefreshStatus());
                smStatusLabel.setForeground(success ? new Color(0, 128, 0) : Color.RED);
            });
        });
    }

    private void setSessionManagerFieldsEnabled(boolean enabled) {
        smLoginUrlField.setEnabled(enabled);
        smMethodCombo.setEnabled(enabled);
        smContentTypeField.setEnabled(enabled);
        smBodyArea.setEnabled(enabled);
        smExtraHeadersArea.setEnabled(enabled);
        smBufferField.setEnabled(enabled);
    }

    // ==================== Periodic UI refresh ====================

    /**
     * Refreshes the token display areas and session manager status every 2 seconds.
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

                    // ---- Session Manager live status ----
                    // JWT expiry countdown (updates every 2 seconds)
                    smJwtExpiryLabel.setText("JWT: " + sessionManager.getJwtExpiryInfo());

                    // Color the JWT label based on expiry status
                    String expiryInfo = sessionManager.getJwtExpiryInfo();
                    if (expiryInfo.startsWith("EXPIRED")) {
                        smJwtExpiryLabel.setForeground(Color.RED);
                    } else if (expiryInfo.startsWith("Expires in")) {
                        try {
                            String numStr = expiryInfo.replace("Expires in ", "").replace("s", "");
                            int remaining = Integer.parseInt(numStr);
                            if (remaining <= 60) {
                                smJwtExpiryLabel.setForeground(Color.ORANGE);
                            } else {
                                smJwtExpiryLabel.setForeground(new Color(0, 128, 0));
                            }
                        } catch (NumberFormatException e) {
                            smJwtExpiryLabel.setForeground(Color.GRAY);
                        }
                    } else {
                        smJwtExpiryLabel.setForeground(Color.GRAY);
                    }

                    // Refresh count
                    smRefreshCountLabel.setText("Refreshes: " + sessionManager.getRefreshCount());

                    // Status label (when enabled and running)
                    if (sessionManager.isEnabled()) {
                        String lastStatus = sessionManager.getLastRefreshStatus();
                        if (lastStatus.startsWith("OK")) {
                            smStatusLabel.setText("Status: Enabled | Last: " + lastStatus);
                            smStatusLabel.setForeground(new Color(0, 128, 0));
                        } else if (lastStatus.startsWith("Failed") || lastStatus.startsWith("Error")) {
                            smStatusLabel.setText("Status: Enabled | Last: " + lastStatus);
                            smStatusLabel.setForeground(Color.ORANGE);
                        }
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
