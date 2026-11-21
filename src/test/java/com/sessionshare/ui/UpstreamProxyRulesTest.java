package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.ui.UserInterface;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class UpstreamProxyRulesTest {
    @Test void installsAndRemovesEachSupportedDestinationPattern() {
        for (String pattern : List.of("api.example.test", "*.example.test", "*")) {
            Fixture burp = new Fixture(true);
            assertTrue(UpstreamProxyRules.current(burp.api).isEmpty());
            UpstreamProxyRules.apply(burp.api, pattern, "laptop.test", 8123);
            JsonArray servers = burp.project.getAsJsonArray("servers");
            assertEquals(1, servers.size());
            JsonObject rule = servers.get(0).getAsJsonObject();
            assertTrue(rule.get("enabled").getAsBoolean());
            assertEquals(pattern, rule.get("destination_host").getAsString());
            assertEquals("laptop.test", rule.get("proxy_host").getAsString());
            assertEquals(8123, rule.get("proxy_port").getAsInt());
            assertEquals("Burp Session Relay forwarding", rule.get("description").getAsString());
            assertEquals(java.util.Set.of("destination_host", "proxy_host", "proxy_port", "description", "enabled", "auth_type"),
                    rule.keySet());
            assertTrue(UpstreamProxyRules.current(burp.api).contains(pattern));
            UpstreamProxyRules.remove(burp.api);
            assertTrue(UpstreamProxyRules.current(burp.api).isEmpty());
            assertTrue(burp.project.getAsJsonArray("servers").isEmpty());
        }
    }

    @Test void updatingManagedRulePreservesExistingRulesAndOrder() {
        Fixture burp = new Fixture(true);
        JsonObject existing = rule("*", "office.test", 8080);
        burp.project.getAsJsonArray("servers").add(existing);
        UpstreamProxyRules.apply(burp.api, "api.example.test", "first.test", 8123);
        UpstreamProxyRules.apply(burp.api, "api.example.test", "second.test", 8124);
        UpstreamProxyRules.apply(burp.api, "api.example.test", "second.test", 8124);
        JsonArray servers = burp.project.getAsJsonArray("servers");
        assertEquals(2, servers.size());
        assertEquals("second.test", servers.get(0).getAsJsonObject().get("proxy_host").getAsString());
        assertEquals(existing, servers.get(1));
        UpstreamProxyRules.remove(burp.api);
        assertEquals(List.of(existing), burp.project.getAsJsonArray("servers").asList());
    }

    @Test void applyingUpdatingAndRemovingWorksWhenBurpOmitsDefaultAuthentication() {
        Fixture burp = new Fixture(false);
        JsonObject dormant = rule("old.example.test", "previous.test", 9100);
        dormant.remove("auth_type");
        burp.project.getAsJsonArray("servers").add(dormant);
        JsonObject original = burp.project.deepCopy();
        JsonObject fallback = rule("*", "fallback.test", 9000);
        burp.user.getAsJsonArray("servers").add(fallback);
        burp.onImport = options -> options.getAsJsonArray("servers").forEach(element -> {
            JsonObject server = element.getAsJsonObject();
            if (server.has("auth_type") && server.get("auth_type").getAsString().equals("none")) {
                server.remove("auth_type");
            }
        });

        UpstreamProxyRules.apply(burp.api, "*.example.test", "first.test", 8080);
        assertTrue(UpstreamProxyRules.current(burp.api).contains("first.test:8080"));
        UpstreamProxyRules.apply(burp.api, "*", "second.test", 8081);
        JsonArray servers = burp.project.getAsJsonArray("servers");
        assertEquals(2, servers.size());
        assertFalse(servers.get(0).getAsJsonObject().has("auth_type"));
        assertEquals("fallback.test", servers.get(1).getAsJsonObject().get("proxy_host").getAsString());
        assertTrue(UpstreamProxyRules.current(burp.api).contains("second.test:8081"));

        UpstreamProxyRules.remove(burp.api);
        assertEquals(original, burp.project);
        assertEquals(List.of(fallback), burp.user.getAsJsonArray("servers").asList());
        assertTrue(UpstreamProxyRules.current(burp.api).isEmpty());
    }

    @Test void verificationReportsChangedPortOrAuthenticationAndRestoresPriorSettings() {
        for (String field : List.of("proxy_port", "auth_type")) {
            Fixture burp = new Fixture(true);
            JsonObject existing = rule("existing.test", "prior-proxy.test", 8755);
            burp.project.getAsJsonArray("servers").add(existing);
            JsonObject original = burp.project.deepCopy();
            burp.onImport = options -> {
                JsonObject first = options.getAsJsonArray("servers").get(0).getAsJsonObject();
                if (!first.has("description")) return;
                if (field.equals("proxy_port")) first.addProperty(field, 9192);
                else first.addProperty(field, "basic");
            };

            IllegalStateException error = assertThrows(IllegalStateException.class,
                    () -> UpstreamProxyRules.apply(burp.api, "target.test", "private-proxy.test", 8989));
            assertTrue(error.getMessage().contains(field), error::getMessage);
            for (String value : List.of("private-proxy.test", "prior-proxy.test", "target.test", "8989", "9192", "basic")) {
                assertFalse(error.getMessage().contains(value), error::getMessage);
            }
            assertEquals(original, burp.project);
            assertTrue(UpstreamProxyRules.current(burp.api).isEmpty());
        }
    }

    @Test void preservesInheritedFallbacksAndRestoresOriginalProjectSettings() {
        Fixture burp = new Fixture(false);
        burp.project.getAsJsonArray("servers").add(rule("inactive.test", "unused.test", 8081));
        JsonObject original = burp.project.deepCopy();
        JsonObject parentRule = rule("*", "user-proxy.test", 8082);
        burp.user.getAsJsonArray("servers").add(parentRule);
        UpstreamProxyRules.apply(burp.api, "api.test", "laptop.test", 9000);
        assertFalse(burp.project.get("use_user_options").getAsBoolean());
        assertEquals(parentRule, burp.project.getAsJsonArray("servers").get(1));
        UpstreamProxyRules.remove(burp.api);
        assertEquals(original, burp.project);
        assertEquals(List.of(parentRule), burp.user.getAsJsonArray("servers").asList());
    }

    @Test void retainsAManuallyAddedRuleWhenRemovingForwarding() {
        Fixture burp = new Fixture(false);
        JsonObject inherited = rule("*", "corporate.test", 8000);
        burp.user.getAsJsonArray("servers").add(inherited);
        UpstreamProxyRules.apply(burp.api, "api.test", "laptop.test", 9000);
        JsonObject manual = rule("tools.test", "office.test", 8080);
        burp.project.getAsJsonArray("servers").add(manual);
        UpstreamProxyRules.remove(burp.api);
        assertFalse(burp.project.get("use_user_options").getAsBoolean());
        assertEquals(List.of(inherited, manual), burp.project.getAsJsonArray("servers").asList());
    }

    @Test void refusesToCopyInheritedAuthenticationIntoTheProject() {
        Fixture burp = new Fixture(false);
        JsonObject authenticated = rule("*", "inherited.test", 8080);
        authenticated.addProperty("auth_type", "basic");
        authenticated.addProperty("username", "test-user");
        authenticated.addProperty("password", "example-password");
        burp.user.getAsJsonArray("servers").add(authenticated);
        assertThrows(IllegalStateException.class,
                () -> UpstreamProxyRules.apply(burp.api, "api.test", "laptop.test", 8081));
        assertEquals(0, burp.importCount);
        assertTrue(burp.extensionData.values().stream().noneMatch(value -> value.contains("example-password")));
    }

    @Test void invalidInputLeavesSettingsUntouched() {
        Fixture burp = new Fixture(true);
        for (String pattern : List.of("", "two.test,other.test", "https://api.test/path")) {
            assertThrows(IllegalArgumentException.class,
                    () -> UpstreamProxyRules.apply(burp.api, pattern, "laptop.test", 8081));
        }
        assertThrows(IllegalArgumentException.class,
                () -> UpstreamProxyRules.apply(burp.api, "api.test", "http://laptop.test", 8081));
        assertThrows(IllegalArgumentException.class,
                () -> UpstreamProxyRules.apply(burp.api, "api.test", "laptop.test", 0));
        assertEquals(0, burp.importCount);
        assertTrue(burp.extensionData.isEmpty());
    }

    @Test void leavesAnExistingManuallyLabelledRuleAlone() {
        Fixture burp = new Fixture(true);
        JsonObject existing = rule("original.test", "other.test", 9001);
        existing.addProperty("description", "Burp Session Relay forwarding");
        burp.project.getAsJsonArray("servers").add(existing);
        assertThrows(IllegalStateException.class,
                () -> UpstreamProxyRules.apply(burp.api, "*", "laptop.test", 8081));
        assertThrows(IllegalStateException.class, () -> UpstreamProxyRules.remove(burp.api));
        assertEquals(0, burp.importCount);
    }

    static MontoyaApi emptyProjectApi() {
        return new Fixture(true).api;
    }

    private static JsonObject rule(String pattern, String host, int port) {
        JsonObject rule = new JsonObject();
        rule.addProperty("destination_host", pattern);
        rule.addProperty("proxy_host", host);
        rule.addProperty("proxy_port", port);
        rule.addProperty("enabled", true);
        rule.addProperty("auth_type", "none");
        return rule;
    }

    private static final class Fixture {
        JsonObject project = new JsonObject();
        final JsonObject user = new JsonObject();
        final Map<String, String> extensionData = new HashMap<>();
        final MontoyaApi api;
        int importCount;
        Consumer<JsonObject> onImport = options -> {};

        Fixture(boolean projectOverride) {
            project.addProperty("use_user_options", !projectOverride);
            project.add("servers", new JsonArray());
            user.add("servers", new JsonArray());
            BurpSuite suite = stub(BurpSuite.class, (proxy, method, args) -> switch (method.getName()) {
                case "exportProjectOptionsAsJson" -> export("project_options", project, args);
                case "exportUserOptionsAsJson" -> export("user_options", user, args);
                case "importProjectOptionsFromJson" -> {
                    JsonObject doc = JsonParser.parseString((String) args[0]).getAsJsonObject();
                    project = doc.getAsJsonObject("project_options").getAsJsonObject("connections")
                            .getAsJsonObject("upstream_proxy");
                    onImport.accept(project);
                    importCount++;
                    yield null;
                }
                default -> throw new AssertionError(method.getName());
            });
            PersistedObject data = stub(PersistedObject.class, (proxy, method, args) -> switch (method.getName()) {
                case "getString" -> extensionData.get((String) args[0]);
                case "setString" -> { extensionData.put((String) args[0], (String) args[1]); yield null; }
                case "deleteString" -> { extensionData.remove((String) args[0]); yield null; }
                default -> throw new AssertionError(method.getName());
            });
            Persistence persistence = stub(Persistence.class, (proxy, method, args) -> {
                if (method.getName().equals("extensionData")) return data;
                throw new AssertionError(method.getName());
            });
            Logging logging = stub(Logging.class, (proxy, method, args) -> null);
            UserInterface ui = stub(UserInterface.class, (proxy, method, args) -> {
                if (method.getName().equals("openSettingsWindow")) return null;
                throw new AssertionError(method.getName());
            });
            api = stub(MontoyaApi.class, (proxy, method, args) -> switch (method.getName()) {
                case "burpSuite" -> suite;
                case "persistence" -> persistence;
                case "logging" -> logging;
                case "userInterface" -> ui;
                default -> throw new AssertionError(method.getName());
            });
        }

        private static String export(String root, JsonObject configuration, Object[] args) {
            assertArrayEquals(new String[]{root + ".connections.upstream_proxy"}, (String[]) args[0]);
            JsonObject connections = new JsonObject();
            connections.add("upstream_proxy", configuration);
            JsonObject options = new JsonObject();
            options.add("connections", connections);
            JsonObject document = new JsonObject();
            document.add(root, options);
            return document.toString();
        }
    }

    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }
}
