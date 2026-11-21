package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.SelectiveSocksProxy;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.SocksRelayServer;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.session.SessionManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/** Settings organized around sharing, routing, session management, and token visibility. */
public class ConfigPanel extends JPanel {
    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private final TokenServer tokenServer;
    private final SocksRelayServer socksRelayServer;
    private final TokenCaptureHandler captureHandler;
    private final TokenPoller tokenPoller;
    private final TokenInjector tokenInjector;
    private final SelectiveSocksProxy selectiveSocksProxy;
    private final SessionManager sessionManager;

    private final JTextField targetField = new JTextField(32);
    private final JRadioButton leaderRadio = new JRadioButton("Leader (receive traffic)");
    private final JRadioButton followerRadio = new JRadioButton("Follower (send traffic)", true);
    private final JComboBox<String> peerPattern = new JComboBox<>(new String[]{"*"});
    private final JTextField peerHost = new JTextField(24);
    private final JTextField peerPort = new JTextField("8080", 8);
    private final JButton removePeerRule = new JButton("Remove forwarding");
    private final JTextArea peerStatus = paragraph("");
    private final Form serviceScope = new Form();
    private final JPanel peerCards = roleCards();
    private final JPanel sharingCards = roleCards();
    private final JPanel routingCards = roleCards();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel overview = new JLabel("Sharing: off   |   VPN routing: off   |   Session manager: off");
    private final JLabel scopeHint = new JLabel("Stop active services before changing the role or target domains.");

    private final JCheckBox allowRemote = new JCheckBox("Allow connections from other devices");
    private final JCheckBox allowDirectIps = new JCheckBox("Allow direct connections to unlisted IP addresses");

    private final JTextField leaderPortField = new JTextField("8888", 8);
    private final JPasswordField leaderPasswordField = new JPasswordField(20);
    private final JTextField leaderCsrfHeaderField = new JTextField("X-CSRF-Token", 20);
    private final DefaultTableModel headerModel = new DefaultTableModel(new String[]{"Response header name"}, 0);
    private final JTable headerTable = new JTable(headerModel);
    private final JButton leaderStartButton = new JButton("Start sharing");
    private final JTextArea leaderStatus = paragraph("Sharing is off.");
    private final JPasswordField relayPasswordField = new JPasswordField(20);
    private final JButton relayButton = new JButton("Start relay");
    private final JTextField socksPortField = new JTextField("1080", 8);
    private final JTextArea socksStatus = paragraph("VPN relay is off.");

    private final JTextField followerHostField = new JTextField(24);
    private final JTextField followerPortField = new JTextField("8888", 8);
    private final JPasswordField followerPasswordField = new JPasswordField(20);
    private final JTextField pollIntervalField = new JTextField("5", 8);
    private final JButton followerConnectButton = new JButton("Connect to leader");
    private final JTextArea followerStatus = paragraph("Not connected.");
    private final JTextField routingHostField = new JTextField(24);
    private final JPasswordField routingPasswordField = new JPasswordField(20);
    private final JTextField followerSocksPortField = new JTextField("1080", 8);
    private final JTextField localSocksPortField = new JTextField("1081", 8);
    private final JButton routingButton = new JButton("Start local routing");
    private final JTextArea routingStatus = paragraph("Local routing is off.");

    private final JCheckBox smEnabled = new JCheckBox("Enable automatic session refresh");
    private final JTextField loginUrlField = new JTextField(32);
    private final JComboBox<String> methodCombo = new JComboBox<>(new String[]{"POST", "GET", "PUT"});
    private final JTextField contentTypeField = new JTextField("application/x-www-form-urlencoded", 24);
    private final JTextArea bodyArea = editor(4);
    private final JTextArea headersArea = editor(3);
    private final JTextField bufferField = new JTextField("30", 8);
    private final JButton testLoginButton = new JButton("Test login request");
    private final JButton refreshButton = new JButton("Refresh now");
    private final JTextArea sessionStatus = paragraph("Automatic refresh is off.");
    private final JLabel expiryStatus = new JLabel("JWT: no token stored");

    private final JCheckBox revealTokens = new JCheckBox("Show token values");
    private final JTextArea tokenDisplay = editor(12);
    private final JLabel tokenSummary = new JLabel("No tokens stored.");
    private final List<JComponent> leaderSettings = new ArrayList<>();
    private final List<JComponent> followerSettings = new ArrayList<>();
    private final List<JComponent> sessionSettings = new ArrayList<>();
    private final Timer uiTimer;
    private boolean sessionBusy;
    private volatile boolean disposed;

    public ConfigPanel(MontoyaApi api, TokenStore tokenStore, TokenServer tokenServer,
                       SocksRelayServer socksRelayServer, TokenCaptureHandler captureHandler,
                       TokenPoller tokenPoller, TokenInjector tokenInjector,
                       SelectiveSocksProxy selectiveSocksProxy, SessionManager sessionManager) {
        this.api = api;
        this.tokenStore = tokenStore;
        this.tokenServer = tokenServer;
        this.socksRelayServer = socksRelayServer;
        this.captureHandler = captureHandler;
        this.tokenPoller = tokenPoller;
        this.tokenInjector = tokenInjector;
        this.selectiveSocksProxy = selectiveSocksProxy;
        this.sessionManager = sessionManager;
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(16, 18, 14, 18));
        add(createHeader(), BorderLayout.NORTH);
        peerCards.add(createBurpToBurp(true), "leader");
        peerCards.add(createBurpToBurp(false), "follower");
        sharingCards.add(createLeaderSharing(), "leader");
        sharingCards.add(createFollowerSharing(), "follower");
        routingCards.add(createLeaderRouting(), "leader");
        routingCards.add(createFollowerRouting(), "follower");
        tabs.addTab("Burp to Burp", scroll(peerCards));
        tabs.addTab("VPN routing", scroll(routingCards));
        tabs.addTab("Session sharing", scroll(sharingCards));
        tabs.addTab("Session manager", createSessionManager());
        tabs.addTab("Tokens & status", createTokenPanel());
        add(tabs, BorderLayout.CENTER);
        overview.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIManager.getColor("Separator.foreground")),
                BorderFactory.createEmptyBorder(10, 0, 0, 0)));
        add(overview, BorderLayout.SOUTH);
        wireActions();
        displayRole();
        updateControls();
        refreshUi();
        uiTimer = new Timer(2000, e -> refreshUi());
        uiTimer.start();
    }

    private JPanel createHeader() {
        JPanel header = new JPanel(new BorderLayout(0, 12));
        JLabel title = new JLabel("Burp Session Relay");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 22f));
        header.add(title, BorderLayout.NORTH);
        Form common = new Form();
        targetField.setName("targetDomains");
        ButtonGroup roles = new ButtonGroup();
        roles.add(leaderRadio);
        roles.add(followerRadio);
        JPanel rolePanel = new JPanel(new GridLayout(1, 2, 14, 0));
        rolePanel.add(followerRadio);
        rolePanel.add(leaderRadio);
        common.field("This computer", rolePanel, null);
        serviceScope.field("Target domains", targetField, "Enter domains separated by commas, e.g. app.example.test, api.example.test. Each includes its subdomains.");
        serviceScope.wide(scopeHint);
        allowRemote.setToolTipText("Permit direct connections to leader services on all network interfaces.");
        serviceScope.wide(allowRemote);
        serviceScope.setVisible(false);
        common.wide(serviceScope);
        header.add(common, BorderLayout.CENTER);
        return header;
    }

    private JPanel createBurpToBurp(boolean leader) {
        Form setup = new Form();
        String title = leader ? "Receive requests in this Burp" : "Send requests to the other Burp";
        String route = "Client  →  follower Burp  →  leader Burp  →  destination";
        JButton settings = new JButton("Open Burp settings");
        settings.addActionListener(e -> api.userInterface().openSettingsWindow());
        if (leader) {
            setup.wide(actions(settings));
            setup.wide(step("Set up the listener",
                    "In Tools → Proxy → Proxy listeners, add or select a running listener. Use a loopback listener such as 127.0.0.1:8080 with SSH port forwarding, or bind to a trusted interface reachable over a protected link."));
            setup.wide(step("Give the follower your listener address",
                    "Share the HTTP listener’s hostname and port. If using SSH, share the follower’s local forwarded address and port. Keep this connection separate from the follower’s own Burp listener."));
        } else {
            peerPattern.setEditable(true);
            peerPattern.setSelectedItem("");
            peerPattern.getEditor().getEditorComponent().getAccessibleContext().setAccessibleName("Destination pattern");
            setup.field("Destination pattern", peerPattern, "Enter a hostname or *.example.test for subdomains. Select * to forward all destinations.");
            setup.field("Receiving Burp host", peerHost, "Use the other Burp’s reachable address, or a local SSH forward on a separate port from your own Burp listener.");
            setup.field("HTTP listener port", peerPort, null);
            JButton apply = new JButton("Apply to this project");
            JButton refresh = new JButton("Refresh status");
            apply.addActionListener(e -> {
                try {
                    UpstreamProxyRules.apply(api, peerPattern.getEditor().getItem().toString().trim(), UiValidation.host(peerHost.getText()),
                            port(peerPort, "HTTP listener port"));
                    refreshPeerState();
                } catch (Exception ex) {
                    showError(peerStatus, "Could not apply forwarding", ex);
                }
            });
            removePeerRule.addActionListener(e -> {
                try {
                    UpstreamProxyRules.remove(api);
                    refreshPeerState();
                } catch (Exception ex) {
                    showError(peerStatus, "Could not remove forwarding", ex);
                }
            });
            refresh.addActionListener(e -> refreshPeerState());
            setup.wide(actions(apply, removePeerRule, refresh));
            setup.wide(peerStatus);
        }
        setup.wide(step("Check both HTTP histories",
                "Send a request through the follower’s Proxy listener. Look for the same path under Proxy → HTTP history on both machines. Forward any paused request if Intercept is on."));
        Form help = new Form();
        if (!leader) {
            help.wide(actions(settings));
            help.wide(paragraph("To configure manually, open Network → Connections → Upstream proxy servers. Put the destination rule above broader matches. Disable any SOCKS setting left over from VPN routing."));
        }
        help.wide(paragraph("To inspect HTTPS on both machines with upstream TLS verification enabled, add the receiving Burp’s public CA under Network → TLS → Custom CA certificates on the follower. TLS pass through on the receiver hides its HTTP details."));
        JToggleButton details = new JToggleButton(leader ? "HTTPS settings" : "Manual setup and HTTPS");
        help.setVisible(false);
        details.addActionListener(e -> {
            help.setVisible(details.isSelected());
            revalidate();
        });
        setup.wide(actions(details));
        setup.wide(help);
        return page(title, route, setup);
    }

    private static JPanel step(String title, String instruction) {
        JPanel step = new JPanel(new BorderLayout(0, 3));
        JLabel heading = new JLabel(title);
        heading.setFont(heading.getFont().deriveFont(Font.BOLD));
        step.add(heading, BorderLayout.NORTH);
        step.add(paragraph(instruction), BorderLayout.CENTER);
        return step;
    }

    private JPanel createLeaderSharing() {
        Form form = new Form();
        form.field("Token-sharing port", leaderPortField, null);
        form.field("Token password", leaderPasswordField, "Give this password only to teammates who should receive credentials. Use a separate password for routing.");
        leaderSettings.addAll(List.of(leaderPortField, leaderPasswordField, leaderCsrfHeaderField, headerTable));
        form.wide(actions(leaderStartButton));
        form.wide(leaderStatus);
        form.wide(paragraph("By default, forward this port through SSH to reach it from another computer. For direct connections over an encrypted network, select Allow connections from other devices."));

        Form extra = new Form();
        extra.field("CSRF header", leaderCsrfHeaderField, "Header used for the CSRF token. Leave empty to disable this header.");
        headerTable.setRowHeight(26);
        headerTable.getTableHeader().setReorderingAllowed(false);
        headerTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        JScrollPane headerScroll = new JScrollPane(headerTable);
        headerScroll.setColumnHeaderView(headerTable.getTableHeader());
        headerScroll.setPreferredSize(new Dimension(300, 100));
        extra.wide(headerScroll);
        JButton addHeader = new JButton("Add header");
        JButton removeHeader = new JButton("Remove selected");
        addHeader.addActionListener(e -> {
            headerModel.addRow(new Object[]{""});
            int row = headerModel.getRowCount() - 1;
            headerTable.editCellAt(row, 0);
            headerTable.requestFocusInWindow();
        });
        removeHeader.addActionListener(e -> {
            int row = headerTable.getSelectedRow();
            if (row >= 0) {
                if (headerTable.isEditing()) headerTable.getCellEditor().stopCellEditing();
                headerModel.removeRow(row);
            }
        });
        leaderSettings.add(addHeader);
        leaderSettings.add(removeHeader);
        extra.wide(actions(addHeader, removeHeader));
        extra.wide(paragraph("Only add response headers your application needs to maintain its session."));
        extra.setVisible(false);
        JToggleButton advanced = new JToggleButton("Additional token headers");
        advanced.addActionListener(e -> {
            extra.setVisible(advanced.isSelected());
            revalidate();
        });
        form.wide(actions(advanced));
        form.wide(extra);
        return page("Share this session", "Share tokens for one application session. Use a trusted encrypted link between teammates for the password and tokens sent over HTTP.", form);
    }

    private JPanel createFollowerSharing() {
        Form form = new Form();
        form.field("Leader address", followerHostField, "The leader's reachable hostname or IP address, without http:// or a port.");
        form.field("Token-sharing port", followerPortField, "Must match the leader's token-sharing port. Default: 8888.");
        form.field("Token password", followerPasswordField, "Use the password from the leader’s Session sharing tab.");
        form.field("Check for tokens every", pollIntervalField, "Seconds between token updates. Default: 5.");
        followerSettings.addAll(List.of(followerHostField, followerPortField, followerPasswordField, pollIntervalField));
        form.wide(actions(followerConnectButton));
        form.wide(followerStatus);
        return page("Use the leader's session", "Use the same target domains as the leader. Connect over a trusted encrypted link to receive session credentials.", form);
    }

    private JPanel createLeaderRouting() {
        Form form = new Form();
        form.field("Relay port", socksPortField, null);
        form.field("Relay password", relayPasswordField, "SOCKS sends this password in plain text. Use an encrypted link between teammates.");
        form.wide(actions(relayButton));
        form.wide(socksStatus);
        form.wide(paragraph("For another computer, forward this port over SSH. To connect directly over a trusted encrypted network, select Allow connections from other devices and give followers this computer’s address."));
        return page("Start a SOCKS relay", "Connect this computer to the target network or VPN first. Starting the relay gives followers a route to the target domains.", form);
    }

    private JPanel createFollowerRouting() {
        Form form = new Form();
        form.field("Leader address", routingHostField, "Hostname or IP address of the relay, or your SSH-forwarded endpoint.");
        form.field("Leader relay port", followerSocksPortField, null);
        form.field("Relay password", routingPasswordField, null);
        form.field("Local SOCKS port", localSocksPortField, "Burp connects here on this computer.");
        allowDirectIps.setToolTipText("An IP may belong to a target domain that Burp resolved locally.");
        form.wide(allowDirectIps);
        form.wide(actions(routingButton));
        form.wide(routingStatus);
        Form instructions = new Form();
        instructions.setBorder(BorderFactory.createTitledBorder("Connect Burp to the local listener"));
        instructions.wide(paragraph("1. In Burp’s network settings, enable SOCKS. Use 127.0.0.1 and the local SOCKS port above. Leave the local username and password blank."));
        instructions.wide(paragraph("2. Enable DNS lookups through SOCKS so the relay can match hostnames. Open a target site through Burp to check the route."));
        instructions.wide(paragraph("3. Disable Burp’s SOCKS setting when you stop local routing."));
        form.wide(instructions);
        return page("Route traffic through a leader", "Target domains use the leader’s network. Other hostnames connect directly. Unlisted IP addresses are blocked by default.", form);
    }

    private JPanel createSessionManager() {
        Form form = new Form();
        form.wide(smEnabled);
        form.field("Login URL", loginUrlField, "Full HTTP or HTTPS URL for the login request.");
        form.field("Method", methodCombo, null);
        form.field("Content-Type", contentTypeField, "For example: application/json or application/x-www-form-urlencoded.");
        form.field("Request body", new JScrollPane(bodyArea), "The body sent by the login request. GET does not send this body.");
        form.field("Extra headers", new JScrollPane(headersArea), "Optional. One header per line, in Name: Value format.");
        form.field("Expiry buffer", bufferField, "Refresh this many seconds before JWT expiry. Default: 30.");
        form.wide(paragraph("Test login request sends one login request and updates stored tokens. A 401/403 triggers refresh for subsequent requests; the failed request is not retried."));
        sessionSettings.addAll(List.of(loginUrlField, methodCombo, contentTypeField, bodyArea, headersArea, bufferField));
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scroll(page("Keep the configured session current", "Optional. Configure a login request for the target domains above. This also works without starting a leader or follower connection.", form)), BorderLayout.CENTER);
        Form controls = new Form();
        controls.setBorder(BorderFactory.createEmptyBorder(8, 14, 10, 14));
        controls.wide(actions(testLoginButton, refreshButton));
        controls.wide(sessionStatus);
        controls.wide(expiryStatus);
        panel.add(controls, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createTokenPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 14, 14, 14));
        JPanel top = new JPanel(new GridLayout(0, 1, 0, 6));
        top.add(tokenSummary);
        top.add(revealTokens);
        top.add(new JLabel("Values are hidden by default, including while screen sharing."));
        panel.add(top, BorderLayout.NORTH);
        tokenDisplay.setEditable(false);
        tokenDisplay.setName("tokenDisplay");
        ((DefaultCaret) tokenDisplay.getCaret()).setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        panel.add(new JScrollPane(tokenDisplay), BorderLayout.CENTER);
        return panel;
    }

    private void wireActions() {
        tabs.addChangeListener(e -> {
            serviceScope.setVisible(tabs.getSelectedIndex() != 0);
            refreshUi();
            if (tabs.getSelectedIndex() == 0 && followerRadio.isSelected()) refreshPeerState();
        });
        leaderRadio.addItemListener(e -> {
            if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED) switchRole();
        });
        followerRadio.addItemListener(e -> {
            if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED) switchRole();
        });
        leaderStartButton.addActionListener(e -> toggleLeader());
        followerConnectButton.addActionListener(e -> toggleFollower());
        relayButton.addActionListener(e -> toggleRelay());
        routingButton.addActionListener(e -> toggleRouting());
        smEnabled.addActionListener(e -> toggleSessionManager());
        testLoginButton.addActionListener(e -> testLogin());
        refreshButton.addActionListener(e -> runSessionRequest(false));
        revealTokens.addActionListener(e -> refreshUi());
    }

    private void displayRole() {
        String role = leaderRadio.isSelected() ? "leader" : "follower";
        ((CardLayout) peerCards.getLayout()).show(peerCards, role);
        ((CardLayout) sharingCards.getLayout()).show(sharingCards, role);
        ((CardLayout) routingCards.getLayout()).show(routingCards, role);
        if (tabs.getSelectedIndex() == 0 && followerRadio.isSelected()) refreshPeerState();
        revalidate();
    }

    private void switchRole() {
        displayRole();
        tokenStore.clear();
        revealTokens.setSelected(false);
        updateControls();
        refreshUi();
    }

    private void refreshPeerState() {
        try {
            String current = UpstreamProxyRules.current(api);
            removePeerRule.setEnabled(!current.isEmpty());
            peerStatus.setText(current.isEmpty() ? "No forwarding rule managed by this extension." : "Project rule   " + current);
        } catch (Exception ex) {
            removePeerRule.setEnabled(false);
            peerStatus.setText("Forwarding status unavailable. Check Burp’s upstream proxy settings.");
        }
    }

    private void toggleLeader() {
        if (tokenServer.isRunning()) {
            captureHandler.setActive(false);
            tokenServer.stop();
            leaderStatus.setText("Sharing is off.");
        } else {
            try {
                String target = UiValidation.credentialScope(targetField.getText());
                int port = port(leaderPortField, "Token-sharing port");
                String password = password(leaderPasswordField);
                String csrf = leaderCsrfHeaderField.getText().trim();
                if (!csrf.isEmpty()) UiValidation.tokenHeaderName(csrf);
                List<String> headers = watchedHeaders();
                if (socksRelayServer.isRunning()) {
                    validateDistinctServices(true, port, password, socksPortField, relayPasswordField);
                }
                tokenStore.setTarget(target);
                tokenStore.setCsrfHeaderName(csrf);
                tokenStore.setWatchedHeaders(headers);
                tokenServer.setPassword(password);
                tokenServer.start(port, leaderBindAddress());
                captureHandler.setActive(true);
            } catch (Exception ex) {
                showError(leaderStatus, "Could not start sharing", ex);
            }
        }
        updateControls();
        refreshUi();
    }

    private void toggleRelay() {
        if (socksRelayServer.isRunning()) {
            socksRelayServer.stop();
            socksStatus.setText("VPN relay is off.");
        } else {
            try {
                String target = UiValidation.scope(targetField.getText());
                int relayPort = port(socksPortField, "Relay port");
                String password = password(relayPasswordField);
                validateSocksPassword(password);
                if (tokenServer.isRunning()) {
                    validateDistinctServices(true, relayPort, password, leaderPortField, leaderPasswordField);
                }
                socksRelayServer.setAllowedScope(target);
                socksRelayServer.setPassword(password);
                socksRelayServer.start(relayPort, leaderBindAddress());
            } catch (Exception ex) {
                showError(socksStatus, "Could not start relay", ex);
            }
        }
        updateControls();
        refreshUi();
    }

    private InetAddress leaderBindAddress() throws UnknownHostException {
        return allowRemote.isSelected() ? null : InetAddress.getByName("127.0.0.1");
    }

    private String leaderListenAddress(JTextField port) {
        return allowRemote.isSelected() ? "all interfaces on port " + port.getText().trim() : "127.0.0.1:" + port.getText().trim();
    }

    private static void validateDistinctServices(boolean sameHost, int port, String password, JTextField activePort,
                                                JPasswordField activePassword) {
        if (sameHost && port == Integer.parseInt(activePort.getText().trim())) {
            throw new IllegalArgumentException("Use different ports for routing and token sharing.");
        }
        if (password.equals(new String(activePassword.getPassword()))) {
            throw new IllegalArgumentException("Use different passwords for routing and token sharing.");
        }
    }

    private void toggleFollower() {
        if (tokenPoller.isConnected()) {
            tokenInjector.setActive(false);
            tokenPoller.stop();
            followerStatus.setText("Disconnected. Local routing is controlled separately in VPN routing.");
        } else {
            try {
                String host = UiValidation.host(followerHostField.getText());
                int port = port(followerPortField, "Token-sharing port");
                String password = password(followerPasswordField);
                int interval = UiValidation.number(pollIntervalField.getText(), "Token update interval", 1, 3600);
                String target = UiValidation.credentialScope(targetField.getText());
                if (selectiveSocksProxy.isRunning()) {
                    validateDistinctServices(host.equalsIgnoreCase(routingHostField.getText().trim()),
                            port, password, followerSocksPortField, routingPasswordField);
                }
                tokenStore.setTarget(target);
                // A different leader may be serving the same domains. Do not reuse prior credentials.
                tokenStore.clear();
                tokenPoller.setLeaderIp(host);
                tokenPoller.setLeaderPort(port);
                tokenPoller.setPassword(password);
                tokenPoller.setPollIntervalSeconds(interval);
                tokenPoller.start();
                tokenInjector.setActive(true);
            } catch (Exception ex) {
                showError(followerStatus, "Could not connect", ex);
            }
        }
        updateControls();
        refreshUi();
    }

    private void toggleRouting() {
        if (selectiveSocksProxy.isRunning()) {
            selectiveSocksProxy.stop();
            routingStatus.setText("Local routing stopped. Disable or change Burp's SOCKS setting.");
        } else {
            try {
                String host = UiValidation.host(routingHostField.getText());
                String password = password(routingPasswordField);
                validateSocksPassword(password);
                String target = UiValidation.scope(targetField.getText());
                int remotePort = port(followerSocksPortField, "Leader VPN relay port");
                int localPort = port(localSocksPortField, "Local SOCKS port");
                if (tokenPoller.isConnected()) {
                    validateDistinctServices(host.equalsIgnoreCase(followerHostField.getText().trim()),
                            remotePort, password, followerPortField, followerPasswordField);
                }
                selectiveSocksProxy.start(localPort, host, remotePort, password, target, allowDirectIps.isSelected());
                routingStatus.setText("Listening at 127.0.0.1:" + localPort + ". Configure Burp below, then open a target site.");
            } catch (Exception ex) {
                showError(routingStatus, "Could not start local routing", ex);
            }
        }
        updateControls();
        refreshUi();
    }

    private void toggleSessionManager() {
        if (smEnabled.isSelected()) {
            try {
                applySessionConfig();
                sessionManager.setEnabled(true);
                sessionStatus.setText("Automatic refresh is on.");
            } catch (IllegalArgumentException ex) {
                smEnabled.setSelected(false);
                showError(sessionStatus, "Check session settings", ex);
            }
        } else {
            sessionManager.setEnabled(false);
            sessionStatus.setText("Automatic refresh is off.");
        }
        updateControls();
        refreshUi();
    }

    /** Read all Swing fields on the event thread before starting a background request. */
    private void applySessionConfig() {
        String target = UiValidation.credentialScope(targetField.getText());
        String loginUrl = UiValidation.loginUrl(loginUrlField.getText());
        int buffer = UiValidation.number(bufferField.getText(), "Expiry buffer", 0, 86400);
        String contentType = contentTypeField.getText().trim();
        if (contentType.contains("\r") || contentType.contains("\n")) {
            throw new IllegalArgumentException("Content-Type must fit on one line.");
        }
        for (String line : headersArea.getText().split("\\R")) {
            if (line.isBlank()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Extra headers need one Name: Value entry per line.");
            UiValidation.headerName(line.substring(0, colon));
        }
        tokenStore.setTarget(target);
        sessionManager.setLoginUrl(loginUrl);
        sessionManager.setLoginMethod((String) methodCombo.getSelectedItem());
        sessionManager.setLoginContentType(contentType);
        sessionManager.setLoginBody(bodyArea.getText());
        sessionManager.setLoginExtraHeaders(headersArea.getText());
        sessionManager.setExpiryBufferSeconds(buffer);
    }

    private void testLogin() {
        try {
            applySessionConfig();
            runSessionRequest(true);
        } catch (IllegalArgumentException ex) {
            showError(sessionStatus, "Check session settings", ex);
        }
    }

    private void runSessionRequest(boolean test) {
        if (sessionBusy || disposed) return;
        boolean wasEnabled = sessionManager.isEnabled();
        if (!test && !wasEnabled) return;
        sessionBusy = true;
        sessionStatus.setText(test ? "Sending login request..." : "Refreshing session...");
        updateControls();
        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                try {
                    if (disposed) return false;
                    if (test) sessionManager.setEnabled(true);
                    return sessionManager.refreshSession();
                } finally {
                    if (test) sessionManager.setEnabled(!disposed && wasEnabled);
                }
            }

            @Override
            protected void done() {
                sessionBusy = false;
                if (disposed) return;
                try {
                    boolean success = get();
                    sessionStatus.setText((success ? "Tokens updated. " : "No successful token update. ")
                            + sessionManager.getLastRefreshStatus());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    sessionStatus.setText("Login request interrupted.");
                } catch (ExecutionException ex) {
                    sessionStatus.setText("Login request failed. See the extension output for details.");
                    api.logging().logToError("[SessionManager] Login request failed: " + ex.getCause().getClass().getSimpleName());
                }
                updateControls();
                refreshUi();
            }
        }.execute();
    }

    private void updateControls() {
        boolean sharing = tokenServer.isRunning();
        boolean following = tokenPoller.isConnected();
        boolean routing = selectiveSocksProxy.isRunning();
        boolean relay = socksRelayServer.isRunning();
        boolean session = sessionManager.isEnabled();
        boolean locked = sharing || following || routing || relay || session || sessionBusy;
        targetField.setEnabled(!locked);
        leaderRadio.setEnabled(!locked);
        followerRadio.setEnabled(!locked);
        for (JComponent c : leaderSettings) c.setEnabled(!sharing && !sessionBusy);
        for (JComponent c : followerSettings) c.setEnabled(!following && !sessionBusy);
        allowRemote.setVisible(leaderRadio.isSelected());
        allowRemote.setEnabled(!sharing && !relay && !sessionBusy);
        allowDirectIps.setEnabled(!routing && !sessionBusy);
        socksPortField.setEnabled(!relay && !sessionBusy);
        relayPasswordField.setEnabled(!relay && !sessionBusy);
        routingHostField.setEnabled(!routing && !sessionBusy);
        routingPasswordField.setEnabled(!routing && !sessionBusy);
        followerSocksPortField.setEnabled(!routing && !sessionBusy);
        localSocksPortField.setEnabled(!routing && !sessionBusy);
        for (JComponent c : sessionSettings) c.setEnabled(!session && !sessionBusy);
        smEnabled.setEnabled(!sessionBusy);
        testLoginButton.setEnabled(!session && !sessionBusy);
        refreshButton.setEnabled(session && !sessionBusy);
        leaderStartButton.setEnabled(!sessionBusy);
        followerConnectButton.setEnabled(!sessionBusy);
        routingButton.setEnabled(!sessionBusy);
        relayButton.setEnabled(!sessionBusy);
        relayButton.setText(relay ? "Stop relay" : "Start relay");
        leaderStartButton.setText(sharing ? "Stop sharing" : "Start sharing");
        followerConnectButton.setText(following ? "Disconnect" : "Connect to leader");
        routingButton.setText(routing ? "Stop local routing" : "Start local routing");
        testLoginButton.setText(sessionBusy && !smEnabled.isSelected() ? "Sending request..." : "Test login request");
        scopeHint.setText(locked ? "Stop active services to edit the role or target domains."
                : "Use * to route all destinations. Session sharing and refresh require named targets.");
    }

    private void refreshUi() {
        if (disposed) return;
        String sharingState = "off";
        if (tokenServer.isRunning()) {
            sharingState = "leader";
            leaderStatus.setText("Listening on " + leaderListenAddress(leaderPortField)
                    + " | Token requests served: " + tokenServer.getRequestCount());
        }
        if (tokenPoller.isConnected()) {
            String error = tokenPoller.getLastError();
            if (!error.isEmpty()) {
                sharingState = "connection error";
                followerStatus.setText("Token connection error: " + error);
            } else if (tokenPoller.getLastFetchTime() == null) {
                sharingState = "waiting for tokens";
                followerStatus.setText("Connecting: waiting for the first token response...");
            } else {
                sharingState = "follower";
                String time = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
                        .format(tokenPoller.getLastFetchTime());
                followerStatus.setText("Tokens received at " + time + " | Leader: " + followerHostField.getText().trim());
            }
        }
        if (socksRelayServer.isRunning()) {
            socksStatus.setText("Listening on " + leaderListenAddress(socksPortField)
                    + " | Active connections: " + socksRelayServer.getActiveConnections());
        }
        String routingState = socksRelayServer.isRunning() ? "leader relay listening"
                : selectiveSocksProxy.isRunning() ? "local listener running" : "off";
        overview.setVisible(tabs.getSelectedIndex() != 0 || tokenServer.isRunning() || tokenPoller.isConnected()
                || socksRelayServer.isRunning() || selectiveSocksProxy.isRunning() || sessionManager.isEnabled() || sessionBusy);
        overview.setText("VPN routing: " + routingState + "   |   Session sharing: " + sharingState
                + "   |   Session manager: " + (sessionBusy ? "request in progress" : sessionManager.isEnabled() ? "on" : "off"));
        expiryStatus.setText("JWT: " + sessionManager.getJwtExpiryInfo()
                + " | Token refreshes: " + sessionManager.getRefreshCount());
        if (sessionManager.isEnabled() && !sessionBusy) {
            sessionStatus.setText("Automatic refresh is on. " + sessionManager.getLastRefreshStatus());
        }
        TokenStore.Snapshot snapshot = tokenStore.getSnapshot();
        int cookieCount = snapshot.cookieString.isEmpty() ? 0 : snapshot.cookieString.split("; ").length;
        tokenSummary.setText("Cookies: " + cookieCount + "   |   JWT: " + (snapshot.jwt.isEmpty() ? "none" : "stored")
                + "   |   CSRF: " + (snapshot.csrfValue.isEmpty() ? "none" : "stored")
                + "   |   Custom headers: " + snapshot.customHeaders.size());
        String display = describeTokens(snapshot, revealTokens.isSelected());
        if (!display.equals(tokenDisplay.getText())) {
            int caret = tokenDisplay.getCaretPosition();
            tokenDisplay.setText(display);
            tokenDisplay.setCaretPosition(Math.min(caret, display.length()));
        }
    }

    static String describeTokens(TokenStore.Snapshot snapshot, boolean reveal) {
        StringBuilder text = new StringBuilder("COOKIES\n");
        if (snapshot.cookieString.isEmpty()) text.append("No cookies stored.\n");
        else for (String cookie : snapshot.cookieString.split("; ")) {
            int separator = cookie.indexOf('=');
            text.append(reveal ? cookie : (separator < 0 ? "Cookie" : cookie.substring(0, separator)) + " = [hidden]").append('\n');
        }
        text.append("\nJWT\n").append(snapshot.jwt.isEmpty() ? "No JWT stored." : reveal ? snapshot.jwt : "[hidden]");
        text.append("\n\nCSRF\n").append(snapshot.csrfValue.isEmpty() ? "No CSRF token stored."
                : snapshot.csrfHeaderName + " = " + (reveal ? snapshot.csrfValue : "[hidden]"));
        text.append("\n\nCUSTOM HEADERS\n");
        if (snapshot.customHeaders.isEmpty()) text.append("No custom headers stored.");
        else snapshot.customHeaders.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry ->
                text.append(entry.getKey()).append(" = ").append(reveal ? entry.getValue() : "[hidden]").append('\n'));
        return text.toString();
    }

    private List<String> watchedHeaders() {
        if (headerTable.isEditing()) headerTable.getCellEditor().stopCellEditing();
        List<String> headers = new ArrayList<>();
        for (int row = 0; row < headerModel.getRowCount(); row++) {
            Object value = headerModel.getValueAt(row, 0);
            if (value != null && !value.toString().isBlank()) headers.add(UiValidation.tokenHeaderName(value.toString()));
        }
        return headers;
    }

    private static int port(JTextField field, String label) {
        return UiValidation.number(field.getText(), label, 1, 65535);
    }

    private static String password(JPasswordField field) {
        String password = new String(field.getPassword());
        if (password.isBlank()) throw new IllegalArgumentException("Enter a password for this service.");
        if (password.indexOf('\r') >= 0 || password.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("The shared password must fit on one line.");
        }
        return password;
    }

    private static void validateSocksPassword(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 255) {
            throw new IllegalArgumentException("The VPN relay password must be at most 255 UTF-8 bytes.");
        }
    }

    private void showError(JTextArea status, String action, Exception error) {
        String detail = error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
        status.setText(action + ": " + detail);
        api.logging().logToError("[Settings] " + action + ": " + detail);
    }

    public void stopUiRefresh() {
        disposed = true;
        uiTimer.stop();
    }

    private static JTextArea editor(int rows) {
        JTextArea area = new JTextArea(rows, 24);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static JTextArea paragraph(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(UIManager.getFont("Label.font").deriveFont(Font.PLAIN));
        area.setBorder(BorderFactory.createEmptyBorder(2, 0, 4, 0));
        return area;
    }

    private static JPanel actions(JComponent... components) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        for (JComponent component : components) {
            if (panel.getComponentCount() > 0) panel.add(Box.createHorizontalStrut(10));
            panel.add(component);
        }
        return panel;
    }

    private static JPanel page(String title, String description, JPanel content) {
        JPanel panel = new JPanel(new BorderLayout(0, 16));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 14, 18, 14));
        JPanel heading = new JPanel(new BorderLayout(0, 6));
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 17f));
        heading.add(label, BorderLayout.NORTH);
        heading.add(paragraph(description), BorderLayout.CENTER);
        panel.add(heading, BorderLayout.NORTH);
        JPanel body = new JPanel(new BorderLayout());
        body.add(content, BorderLayout.NORTH);
        panel.add(body, BorderLayout.CENTER);
        return panel;
    }

    private static JPanel roleCards() {
        return new JPanel(new CardLayout()) {
            @Override public Dimension getPreferredSize() {
                for (Component child : getComponents()) {
                    if (child.isVisible()) return child.getPreferredSize();
                }
                return super.getPreferredSize();
            }
        };
    }

    private static JScrollPane scroll(JComponent content) {
        JPanel viewport = new JPanel(new BorderLayout()) {
            @Override public Dimension getPreferredSize() {
                Dimension preferred = super.getPreferredSize();
                if (getParent() instanceof JViewport parent && parent.getWidth() > 0) {
                    preferred.width = parent.getWidth();
                }
                return preferred;
            }
        };
        viewport.add(content, BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(viewport);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(18);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        return scroll;
    }

    private static final class Form extends JPanel {
        private int row;

        Form() { super(new GridBagLayout()); }

        void field(String text, JComponent control, String hint) {
            GridBagConstraints labelConstraints = constraints(0, row);
            JLabel label = new JLabel(text);
            label.setLabelFor(control);
            add(label, labelConstraints);
            GridBagConstraints controlConstraints = constraints(1, row++);
            controlConstraints.weightx = 1;
            controlConstraints.fill = GridBagConstraints.HORIZONTAL;
            control.setMinimumSize(new Dimension(100, control.getPreferredSize().height));
            if (control.getAccessibleContext() != null) control.getAccessibleContext().setAccessibleName(text);
            add(control, controlConstraints);
            if (hint != null) {
                GridBagConstraints hintConstraints = constraints(1, row++);
                hintConstraints.weightx = 1;
                hintConstraints.fill = GridBagConstraints.HORIZONTAL;
                add(paragraph(hint), hintConstraints);
                control.setToolTipText(hint);
            }
        }

        void wide(JComponent component) {
            GridBagConstraints constraints = constraints(0, row++);
            constraints.gridwidth = 2;
            constraints.weightx = 1;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            add(component, constraints);
        }

        private GridBagConstraints constraints(int column, int row) {
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.gridx = column;
            constraints.gridy = row;
            constraints.anchor = GridBagConstraints.NORTHWEST;
            constraints.insets = new Insets(4, 0, 4, column == 0 ? 16 : 0);
            return constraints;
        }
    }
}
