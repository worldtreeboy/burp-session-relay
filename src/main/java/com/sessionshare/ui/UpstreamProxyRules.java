package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Edits only Burp's upstream HTTP proxy section in the current project. */
final class UpstreamProxyRules {
    private static final String PROJECT = "project_options";
    private static final String USER = "user_options";
    private static final String PATH = ".connections.upstream_proxy";
    private static final String LABEL = "Burp Session Relay forwarding";
    private static final String MANAGED = "upstream.managed";
    private static final String INHERITED = "upstream.previous.project";
    private static final String FALLBACKS = "upstream.copied.fallbacks";

    private UpstreamProxyRules() {}

    static synchronized void apply(MontoyaApi api, String pattern, String host, int port) {
        String destination = pattern.trim();
        if (!destination.equals("*")) {
            String domain = destination.startsWith("*.") ? destination.substring(2) : destination;
            try {
                UiValidation.host(domain);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Enter a hostname, *.example.com, or * for all destinations.");
            }
        }
        String proxyHost = UiValidation.host(host);
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Enter a proxy port from 1 to 65535.");

        JsonObject previous = project(api);
        PersistedObject data = api.persistence().extensionData();
        JsonArray previousServers = servers(previous);
        JsonObject managed = managedRule(previousServers, data);
        JsonArray others = withoutManaged(previousServers, managed);
        boolean inherited = usesUser(previous);
        if (inherited) {
            JsonObject user = section(api.burpSuite().exportUserOptionsAsJson(USER + PATH), USER);
            others = servers(user);
            if (hasAuthentication(others) || hasAuthentication(previousServers)) {
                throw new IllegalStateException("This project inherits upstream settings and has an authenticated rule. Use Burp settings to configure forwarding without copying saved credentials.");
            }
        }
        if (inherited && others.asList().stream().anyMatch(UpstreamProxyRules::hasLabel)) {
            throw new IllegalStateException("An inherited rule already uses the forwarding label. Choose another description for it in Burp settings.");
        }
        if (inherited) {
            // The inactive project list can differ from the effective user list. Keep it for removal.
            JsonObject dormant = previous.deepCopy();
            dormant.add("servers", withoutManaged(previousServers, managed));
            data.setString(INHERITED, dormant.toString());
        } else if (managed == null) {
            data.deleteString(INHERITED);
            data.deleteString(FALLBACKS);
        }
        JsonObject route = new JsonObject();
        route.addProperty("description", LABEL);
        route.addProperty("enabled", true);
        route.addProperty("auth_type", "none");
        route.addProperty("destination_host", destination);
        route.addProperty("proxy_host", proxyHost);
        route.addProperty("proxy_port", port);
        JsonArray ordered = new JsonArray();
        ordered.add(route);
        ordered.addAll(others);
        JsonObject next = previous.deepCopy();
        next.add("servers", ordered);
        next.addProperty("use_user_options", false);
        JsonObject accepted = writeVerified(api, previous, next);
        data.setString(MANAGED, "true");
        if (inherited) {
            // Track Burp's serialized defaults so a normal round trip still restores inheritance.
            JsonArray acceptedRules = servers(accepted);
            data.setString(FALLBACKS, withoutManaged(acceptedRules, acceptedRules.get(0).getAsJsonObject()).toString());
        }
    }

    static synchronized void remove(MontoyaApi api) {
        JsonObject previous = project(api);
        PersistedObject data = api.persistence().extensionData();
        JsonObject managed = managedRule(servers(previous), data);
        if (managed == null) return;
        JsonArray others = withoutManaged(servers(previous), managed);
        JsonObject next = previous.deepCopy();
        next.add("servers", others);
        String saved = data.getString(INHERITED);
        String baseline = data.getString(FALLBACKS);
        if (saved != null && baseline != null && others.equals(JsonParser.parseString(baseline))) {
            // No one edited the other project rules, so it is safe to restore inheritance.
            next = JsonParser.parseString(saved).getAsJsonObject();
        }
        writeVerified(api, previous, next);
        data.deleteString(MANAGED);
        data.deleteString(INHERITED);
        data.deleteString(FALLBACKS);
    }

    static synchronized String current(MontoyaApi api) {
        JsonObject settings = project(api);
        JsonObject route = managedRule(servers(settings), api.persistence().extensionData());
        if (route == null) return "";
        String state = usesUser(settings) || !route.get("enabled").getAsBoolean() ? "Inactive: " :
                servers(settings).get(0) != route ? "Below other rules: " : "";
        String pattern = route.get("destination_host").getAsString();
        return state + (pattern.equals("*") ? "All destinations (*)" : pattern) + " → "
                + route.get("proxy_host").getAsString() + ":" + route.get("proxy_port").getAsInt();
    }

    private static JsonObject project(MontoyaApi api) {
        return section(api.burpSuite().exportProjectOptionsAsJson(PROJECT + PATH), PROJECT);
    }

    private static JsonObject section(String json, String level) {
        try {
            JsonObject options = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject(level)
                    .getAsJsonObject("connections").getAsJsonObject("upstream_proxy");
            servers(options);
            if (level.equals(PROJECT)) usesUser(options);
            return options;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not read Burp's upstream proxy settings. Open Burp settings to configure forwarding.");
        }
    }

    private static JsonArray servers(JsonObject options) {
        return options.get("servers").getAsJsonArray();
    }

    private static boolean usesUser(JsonObject options) {
        return options.get("use_user_options").getAsBoolean();
    }

    private static boolean nonempty(JsonObject object, String field) {
        return object.has(field) && !object.get(field).isJsonNull() && !object.get(field).getAsString().isEmpty();
    }

    private static boolean hasAuthentication(JsonArray rules) {
        for (JsonElement element : rules) {
            JsonObject rule = element.getAsJsonObject();
            if ((nonempty(rule, "auth_type") && !"none".equalsIgnoreCase(rule.get("auth_type").getAsString()))
                    || nonempty(rule, "password") || nonempty(rule, "username")) return true;
        }
        return false;
    }

    private static boolean hasLabel(JsonElement element) {
        JsonObject rule = element.getAsJsonObject();
        return nonempty(rule, "description") && LABEL.equals(rule.get("description").getAsString());
    }

    private static JsonObject managedRule(JsonArray rules, PersistedObject data) {
        JsonObject found = null;
        for (JsonElement element : rules) {
            if (!hasLabel(element)) continue;
            if (found != null || !"true".equals(data.getString(MANAGED))) {
                throw new IllegalStateException("An existing upstream rule also uses the Burp Session Relay forwarding label. Give it a distinct description in Burp settings.");
            }
            found = element.getAsJsonObject();
        }
        return found;
    }

    private static JsonArray withoutManaged(JsonArray rules, JsonObject managed) {
        JsonArray others = new JsonArray();
        for (JsonElement rule : rules) if (rule != managed) others.add(rule);
        return others;
    }

    /** Compare the exported settings without including addresses or credentials in diagnostics. */
    private static String difference(JsonObject actual, JsonObject expected) {
        if (usesUser(actual) != usesUser(expected)) return "The project override (use_user_options) differs.";
        JsonArray a = servers(actual), e = servers(expected);
        if (a.size() != e.size()) return "Burp returned a different number of upstream rules.";
        for (int i = 0; i < e.size(); i++) {
            JsonObject wanted = e.get(i).getAsJsonObject();
            JsonObject received = a.get(i).getAsJsonObject();
            String prefix = "Upstream rule " + (i + 1) + " differs in ";
            // The desktop exporter can omit the default authentication mode for an unauthenticated proxy.
            if (!authenticationMode(wanted).equalsIgnoreCase(authenticationMode(received))) {
                return prefix + "auth_type.";
            }
            for (var field : wanted.entrySet()) {
                if (!field.getKey().equals("auth_type") && !field.getValue().equals(received.get(field.getKey()))) {
                    return prefix + field.getKey() + ".";
                }
            }
        }
        return "";
    }

    private static String authenticationMode(JsonObject rule) {
        return rule.has("auth_type") ? rule.get("auth_type").getAsString() : "none";
    }

    private static JsonObject writeVerified(MontoyaApi api, JsonObject previous, JsonObject next) {
        // Re-read before replacing the ordered list so edits made since opening the form survive.
        if (!project(api).equals(previous)) throw new IllegalStateException("Upstream settings changed. Refresh and try again.");
        String detail;
        try {
            write(api, next);
            JsonObject accepted = project(api);
            detail = difference(accepted, next);
            if (detail.isEmpty()) return accepted;
        } catch (RuntimeException e) {
            // Montoya imports can also fail after applying part of a configuration.
            detail = "Burp's settings API raised " + e.getClass().getSimpleName() + ".";
        }
        try {
            write(api, previous);
            if (!difference(project(api), previous).isEmpty()) throw new IllegalStateException();
        } catch (RuntimeException e) {
            throw new IllegalStateException(detail + " Restore could not be verified. Check Burp's upstream proxy settings.");
        }
        throw new IllegalStateException(detail + " The previous upstream settings were restored.");
    }

    private static void write(MontoyaApi api, JsonObject options) {
        JsonObject connections = new JsonObject();
        connections.add("upstream_proxy", options);
        JsonObject project = new JsonObject();
        project.add("connections", connections);
        JsonObject root = new JsonObject();
        root.add(PROJECT, project);
        api.burpSuite().importProjectOptionsFromJson(root.toString());
    }
}
