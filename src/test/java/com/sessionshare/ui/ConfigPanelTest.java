package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.sessionshare.follower.SelectiveSocksProxy;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.SocksRelayServer;
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
import java.lang.reflect.Proxy;
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
                assertEquals(List.of("Session sharing", "VPN routing", "Session manager", "Tokens & status"),
                        java.util.stream.IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
                assertTrue(button(panel, "Leader: share my session").isSelected());
                button(panel, "Follower: use a shared session").doClick();
                assertTrue(button(panel, "Follower: use a shared session").isSelected());
                for (int index = 0; index < tabs.getTabCount(); index++) tabs.setSelectedIndex(index);
                assertFalse(fixture.tokenServer.isRunning());
                assertFalse(fixture.relay.isRunning());
                assertFalse(fixture.poller.isConnected());
                assertFalse(fixture.proxy.isRunning());
                assertFalse(fixture.session.isEnabled());
            }
        });
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
                    render(panel, size, output, "leader-sharing");
                    button(panel, "Additional token headers").doClick();
                    render(panel, size, output, "leader-sharing-headers");
                    renderAtBottom(panel, size, output, "leader-sharing-headers-bottom");
                    button(panel, "Additional token headers").doClick();
                    JTabbedPane tabs = find(panel, JTabbedPane.class).get(0);
                    tabs.setSelectedIndex(1);
                    render(panel, size, output, "leader-routing");
                    button(panel, "Follower: use a shared session").doClick();
                    tabs.setSelectedIndex(0);
                    render(panel, size, output, "follower-sharing");
                    tabs.setSelectedIndex(1);
                    render(panel, size, output, "follower-routing");
                    renderAtBottom(panel, size, output, "follower-routing-bottom");
                    tabs.setSelectedIndex(2);
                    render(panel, size, output, "session-manager");
                    renderAtBottom(panel, size, output, "session-manager-bottom");
                    fixture.store.fromJson(sampleTokens().toJson());
                    button(panel, "Show token values").doClick();
                    button(panel, "Show token values").doClick();
                    tabs.setSelectedIndex(3);
                    render(panel, size, output, "tokens-masked");
                    assertFalse(fixture.tokenServer.isRunning());
                    assertFalse(fixture.relay.isRunning());
                    assertFalse(fixture.poller.isConnected());
                    assertFalse(fixture.proxy.isRunning());
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
        store.applyCapturedResponse(Map.of("session", "cookie-preview-value"), "jwt-preview-value", "csrf-preview-value",
                Map.of("X-Device", "header-preview-value"));
        return store;
    }

    private static MontoyaApi apiStub() {
        Logging logging = (Logging) Proxy.newProxyInstance(Logging.class.getClassLoader(), new Class<?>[]{Logging.class},
                (proxy, method, args) -> null);
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("logging")) return logging;
                    throw new AssertionError("UI preview must not call " + method.getName());
                });
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
        final MontoyaApi api = apiStub();
        final TokenServer tokenServer = new TokenServer(api, store);
        final SocksRelayServer relay = new SocksRelayServer(api);
        final TokenPoller poller = new TokenPoller(api, store);
        final SelectiveSocksProxy proxy = new SelectiveSocksProxy(api);
        final SessionManager session = new SessionManager(api, store);
        final ConfigPanel panel = new ConfigPanel(api, store, tokenServer, relay,
                new TokenCaptureHandler(api, store), poller, new TokenInjector(api, store, poller), proxy, session);

        @Override public void close() {
            assertTrue(SwingUtilities.isEventDispatchThread());
            panel.stopUiRefresh();
        }
    }
}
