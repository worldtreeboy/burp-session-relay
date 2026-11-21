package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.session.SessionManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ConfigPanelTest {
    @BeforeAll static void useHeadlessSwing() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test void tokenSummaryHidesEveryCredentialValueByDefault() {
        TokenStore store = sampleTokens();
        String hidden = ConfigPanel.describeTokens(store.getSnapshot(), false);
        String revealed = ConfigPanel.describeTokens(store.getSnapshot(), true);

        for (String value : List.of("cookie-preview-value", "jwt-preview-value", "csrf-preview-value", "header-preview-value")) {
            assertFalse(hidden.contains(value));
            assertTrue(revealed.contains(value));
        }
        assertTrue(hidden.contains("session = [hidden]"));
        assertTrue(hidden.contains("X-CSRF-Token = [hidden]"));
        assertTrue(hidden.contains("X-Device = [hidden]"));
    }

    @Test void roleAndTabChangesDoNotStartServices() throws Exception {
        onEdt(() -> {
            try (Fixture fixture = new Fixture()) {
                ConfigPanel panel = fixture.panel;
                JTabbedPane tabs = find(panel, JTabbedPane.class).get(0);
                assertEquals(List.of("Burp to Burp", "Session sharing", "Session manager", "Tokens & status"),
                        java.util.stream.IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
                assertEquals("Burp to Burp", tabs.getTitleAt(tabs.getSelectedIndex()));
                assertTrue(button(panel, "Follower (send traffic)").isSelected());
                assertTrue(field(panel, "Destination pattern").getText().isEmpty());
                button(panel, "Leader (receive traffic)").doClick();
                assertTrue(button(panel, "Leader (receive traffic)").isSelected());
                for (int index = 0; index < tabs.getTabCount(); index++) tabs.setSelectedIndex(index);
                assertFalse(fixture.tokenServer.isRunning());
                assertFalse(fixture.poller.isConnected());
                assertFalse(fixture.session.isEnabled());
            }
        });
    }

    @Test void firstTabSetsReplacesAndRemovesNativeForwarding() throws Exception {
        onEdt(() -> {
            try (Fixture fixture = new Fixture()) {
                ConfigPanel panel = fixture.panel;
                assertTrue(button(panel, "Follower (send traffic)").isSelected());
                assertFalse(button(panel, "Remove forwarding").isEnabled());
                JTextField pattern = field(panel, "Destination pattern");
                pattern.setText("api.example.test");
                field(panel, "Receiving Burp host").setText("work-laptop.example.test");
                button(panel, "Apply to this project").doClick();
                assertEquals("api.example.test → work-laptop.example.test:8080", UpstreamProxyRules.current(fixture.api));
                assertTrue(button(panel, "Remove forwarding").isEnabled());

                JComboBox<?> patternChoices = find(panel, JComboBox.class).stream()
                        .filter(combo -> "Destination pattern".equals(combo.getAccessibleContext().getAccessibleName()))
                        .findFirst().orElseThrow();
                patternChoices.setSelectedItem("*");
                button(panel, "Apply to this project").doClick();
                button(panel, "Refresh status").doClick();
                assertEquals("All destinations (*) → work-laptop.example.test:8080", UpstreamProxyRules.current(fixture.api));
                assertTrue(find(panel, JTextArea.class).stream().anyMatch(area ->
                        area.getText().contains("All destinations (*) → work-laptop.example.test:8080") && visibleInRole(area)));

                button(panel, "Remove forwarding").doClick();
                assertEquals("", UpstreamProxyRules.current(fixture.api));
                assertFalse(fixture.tokenServer.isRunning());
                assertFalse(fixture.capture.isActive());
                assertFalse(fixture.poller.isConnected());
            }
        });
    }

    @Test void leaderSharingLocksItsScopeAndDefaultsToLoopback() throws Exception {
        onEdt(() -> {
            try (Fixture fixture = new Fixture()) {
                ConfigPanel panel = fixture.panel;
                JTabbedPane tabs = find(panel, JTabbedPane.class).get(0);
                button(panel, "Leader (receive traffic)").doClick();
                AbstractButton allowRemote = button(panel, "Allow connections from other devices");
                assertFalse(visibleInRole(allowRemote));

                tabs.setSelectedIndex(tabs.indexOfTab("Session manager"));
                assertTrue(field(panel, "Target domains").isEnabled());
                assertFalse(visibleInRole(allowRemote));
                tabs.setSelectedIndex(tabs.indexOfTab("Session sharing"));
                assertTrue(visibleInRole(allowRemote));
                assertFalse(allowRemote.isSelected());

                JTextField targets = field(panel, "Target domains");
                targets.setText("example.test");
                int tokenPort = freeLoopbackPort();
                field(panel, "Token-sharing port").setText(Integer.toString(tokenPort));
                field(panel, "Token password").setText("token-secret");
                button(panel, "Start sharing").doClick();
                assertTrue(fixture.tokenServer.isRunning());
                assertTrue(fixture.capture.isActive());
                assertFalse(allowRemote.isEnabled());
                assertFalse(targets.isEnabled());
                assertTrue(find(panel, JTextArea.class).stream().anyMatch(area ->
                        area.getText().contains("Listening on 127.0.0.1:" + tokenPort) && visibleInRole(area)));
                button(panel, "Stop sharing").doClick();
                assertFalse(fixture.capture.isActive());
                assertFalse(fixture.tokenServer.isRunning());
                assertTrue(allowRemote.isEnabled());
                assertTrue(targets.isEnabled());
                tabs.setSelectedIndex(tabs.indexOfTab("Tokens & status"));
                assertFalse(visibleInRole(allowRemote));
                assertFalse(visibleInRole(targets));
            }
        });
    }

    @Test void followerCannotStartTokenSharingForAllDestinations() throws Exception {
        onEdt(() -> {
            try (Fixture fixture = new Fixture()) {
                ConfigPanel panel = fixture.panel;
                JTabbedPane tabs = find(panel, JTabbedPane.class).get(0);
                tabs.setSelectedIndex(tabs.indexOfTab("Session sharing"));
                assertFalse(visibleInRole(button(panel, "Allow connections from other devices")));
                field(panel, "Target domains").setText("*");
                field(panel, "Leader address").setText("127.0.0.1");
                field(panel, "Token password").setText("token-secret");
                button(panel, "Connect to leader").doClick();
                assertFalse(fixture.poller.isConnected());
                assertTrue(find(panel, JTextArea.class).stream().anyMatch(area ->
                        area.getText().contains("Replace *") && visibleInRole(area)));
            }
        });
    }

    private static int freeLoopbackPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static JTextField field(Container root, String accessibleName) {
        return find(root, JTextField.class).stream()
                .filter(field -> accessibleName.equals(field.getAccessibleContext().getAccessibleName()))
                .filter(ConfigPanelTest::visibleInRole)
                .findFirst().orElseThrow(() -> new AssertionError("Missing field " + accessibleName));
    }

    private static boolean visibleInRole(Component component) {
        for (Component current = component; current != null; current = current.getParent()) {
            if (!current.isVisible()) return false;
        }
        return true;
    }

    @Test void rendersHeadlessUiPreviewsAtDesktopAndCompactSizes() throws Exception {
        Path output = Path.of("build", "ui-preview");
        Files.createDirectories(output);
        onEdt(() -> {
            for (Dimension size : List.of(new Dimension(1000, 800), new Dimension(760, 700))) {
                try (Fixture fixture = new Fixture()) {
                    ConfigPanel panel = fixture.panel;
                    find(panel, JTextField.class).stream().filter(field -> "targetDomains".equals(field.getName()))
                            .findFirst().orElseThrow().setText("example.test, *.internal.test");
                    JTabbedPane tabs = find(panel, JTabbedPane.class).get(0);
                    button(panel, "Leader (receive traffic)").doClick();
                    render(panel, size, output, "leader-burp-to-burp");
                    tabs.setSelectedIndex(tabs.indexOfTab("Session sharing"));
                    render(panel, size, output, "leader-sharing");
                    button(panel, "Additional token headers").doClick();
                    render(panel, size, output, "leader-sharing-headers");
                    renderAtBottom(panel, size, output, "leader-sharing-headers-bottom");
                    button(panel, "Additional token headers").doClick();
                    button(panel, "Follower (send traffic)").doClick();
                    render(panel, size, output, "follower-sharing");
                    tabs.setSelectedIndex(tabs.indexOfTab("Burp to Burp"));
                    field(panel, "Destination pattern").setText("api.example.test");
                    field(panel, "Receiving Burp host").setText("work-laptop.example.test");
                    render(panel, size, output, "follower-burp-to-burp");
                    tabs.setSelectedIndex(tabs.indexOfTab("Session manager"));
                    render(panel, size, output, "session-manager");
                    renderAtBottom(panel, size, output, "session-manager-bottom");
                    fixture.store.setTarget("example.test");
                    fixture.store.fromJson(sampleTokens().toJson());
                    button(panel, "Show token values").doClick();
                    button(panel, "Show token values").doClick();
                    tabs.setSelectedIndex(tabs.indexOfTab("Tokens & status"));
                    render(panel, size, output, "tokens-masked");
                    assertFalse(fixture.tokenServer.isRunning());
                    assertFalse(fixture.poller.isConnected());
                }
            }
        });
    }

    private static void render(ConfigPanel panel, Dimension size, Path output, String name) throws Exception {
        assertTrue(SwingUtilities.isEventDispatchThread());
        panel.setSize(size);
        // Wrapped text depends on the viewport width; let preferred heights settle.
        for (int pass = 0; pass < 8; pass++) layoutTree(panel);
        BufferedImage image = new BufferedImage(size.width, size.height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setColor(panel.getBackground());
            graphics.fillRect(0, 0, size.width, size.height);
            panel.printAll(graphics);
        } finally {
            graphics.dispose();
        }
        Path file = output.resolve(name + "-" + size.width + "x" + size.height + ".png");
        assertTrue(ImageIO.write(image, "png", file.toFile()));
        assertTrue(Files.size(file) > 1000);
    }

    private static void renderAtBottom(ConfigPanel panel, Dimension size, Path output, String name) throws Exception {
        Component selected = find(panel, JTabbedPane.class).get(0).getSelectedComponent();
        JScrollPane scroll = selected instanceof JScrollPane pane ? pane
                : find((Container) selected, JScrollPane.class).get(0);
        scroll.getVerticalScrollBar().setValue(scroll.getVerticalScrollBar().getMaximum());
        render(panel, size, output, name);
        scroll.getVerticalScrollBar().setValue(0);
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) {
            if (child instanceof Container nested) layoutTree(nested);
        }
    }

    private static AbstractButton button(Container root, String text) {
        return find(root, AbstractButton.class).stream().filter(button -> text.equals(button.getText()))
                .findFirst().orElseThrow();
    }

    private static <T extends Component> List<T> find(Container root, Class<T> type) {
        List<T> matches = new ArrayList<>();
        for (Component child : root.getComponents()) {
            if (type.isInstance(child)) matches.add(type.cast(child));
            if (child instanceof Container nested) matches.addAll(find(nested, type));
        }
        return matches;
    }

    private static TokenStore sampleTokens() {
        TokenStore store = new TokenStore();
        store.setTarget("example.test");
        store.setCsrfHeaderName("X-CSRF-Token");
        store.setWatchedHeaders(List.of("X-Device"));
        store.applyCapturedResponseForUrl("https://example.test/", List.of("session=cookie-preview-value"), "jwt-preview-value", "csrf-preview-value",
                Map.of("X-Device", "header-preview-value"));
        return store;
    }

    private static void onEdt(CheckedTask task) throws Exception {
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    task.run();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Error error) throw error;
            if (e.getCause() instanceof RuntimeException exception && exception.getCause() instanceof Exception cause) throw cause;
            throw e;
        }
    }

    @FunctionalInterface private interface CheckedTask {
        void run() throws Exception;
    }

    private static final class Fixture implements AutoCloseable {
        final TokenStore store = new TokenStore();
        final MontoyaApi api = UpstreamProxyRulesTest.emptyProjectApi();
        final TokenServer tokenServer = new TokenServer(api, store);
        final TokenPoller poller = new TokenPoller(api, store);
        final SessionManager session = new SessionManager(api, store);
        final TokenCaptureHandler capture = new TokenCaptureHandler(api, store);
        final ConfigPanel panel = new ConfigPanel(api, store, tokenServer,
                capture, poller, new TokenInjector(api, store, poller), session);

        @Override public void close() {
            assertTrue(SwingUtilities.isEventDispatchThread());
            panel.stopUiRefresh();
            poller.stop();
            tokenServer.stop();
        }
    }
}
