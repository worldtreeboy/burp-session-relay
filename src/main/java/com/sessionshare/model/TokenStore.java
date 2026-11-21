package com.sessionshare.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sessionshare.util.ScopeMatcher;

import com.sessionshare.util.SetCookieParser;
import com.sessionshare.util.SetCookieParser.CookieKey;
import com.sessionshare.util.SetCookieParser.StoredCookie;

import java.net.URI;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe storage for session tokens (cookies, JWT, CSRF).
 * Accessed concurrently by Burp proxy threads, the embedded HTTP server,
 * and the follower polling thread.
 */
public class TokenStore {

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Map<CookieKey, StoredCookie> cookies = new LinkedHashMap<>();
    private volatile String jwt = "";
    private volatile String csrfHeaderName = "";
    private volatile String csrfValue = "";
    private volatile String target = "";
    private volatile Instant updatedAt = Instant.now();
    private volatile boolean loginMacroInProgress = false;
    private volatile String loginMacroUrl = "";

    // Custom headers: header name -> captured value
    // The leader configures which header names to watch; values are captured from traffic.
    private final ConcurrentHashMap<String, String> customHeaders = new ConcurrentHashMap<>();
    // Header names the leader is watching for (configured via UI)
    private final ConcurrentHashMap<String, Boolean> watchedHeaders = new ConcurrentHashMap<>();

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // --- Target scope ---

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        String nextTarget = target == null ? "" : target.trim();
        lock.writeLock().lock();
        try {
            if (!this.target.equals(nextTarget)) {
                clearTokens();
                this.target = nextTarget;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void beginLoginMacro(String url) {
        loginMacroUrl = url == null ? "" : url;
        loginMacroInProgress = true;
    }

    public void endLoginMacro() {
        loginMacroInProgress = false;
    }

    public boolean shouldBypassInjection(String url) {
        return loginMacroInProgress && loginMacroUrl.equals(url);
    }

    // --- Cookies ---

    /**
     * Build a Cookie header string: "name1=value1; name2=value2"
     */
    public String getCookieString() {
        lock.readLock().lock();
        try {
            return buildCookieString(null);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Return pooled cookies only when the destination is in the current local scope. */
    public String getCookieStringForUrl(String url) {
        lock.readLock().lock();
        try {
            return ScopeMatcher.matchesUrl(url, target) ? buildCookieString(URI.create(url)) : "";
        } finally {
            lock.readLock().unlock();
        }
    }

    private String buildCookieString(URI destination) {
        long now = Instant.now().getEpochSecond();
        return cookies.values().stream()
                .filter(cookie -> cookie.expiresAt() > now && (destination == null || cookie.matches(destination)))
                .sorted(Comparator.comparingInt((StoredCookie cookie) -> cookie.path().length()).reversed())
                .map(cookie -> cookie.name() + "=" + cookie.value())
                .collect(Collectors.joining("; "));
    }

    // --- JWT ---

    public String getJwt() {
        return jwt;
    }

    // --- CSRF ---

    public String getCsrfHeaderName() {
        return csrfHeaderName;
    }

    public void setCsrfHeaderName(String csrfHeaderName) {
        String nextName = csrfHeaderName == null ? "" : csrfHeaderName.trim();
        lock.writeLock().lock();
        try {
            if (!this.csrfHeaderName.equalsIgnoreCase(nextName)) {
                csrfValue = "";
                updatedAt = Instant.now();
            }
            this.csrfHeaderName = nextName;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String getCsrfValue() {
        return csrfValue;
    }

    // --- Custom Headers ---

    /**
     * Add a header name to watch for in responses (leader-side config).
     */
    public void addWatchedHeader(String headerName) {
        if (headerName == null || headerName.isBlank()) return;
        lock.writeLock().lock();
        try {
            String name = headerName.trim();
            watchedHeaders.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
            watchedHeaders.put(name, Boolean.TRUE);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Remove a header name from the watch list.
     */
    public void removeWatchedHeader(String headerName) {
        if (headerName == null) return;
        String name = headerName.trim();
        lock.writeLock().lock();
        try {
            watchedHeaders.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
            if (customHeaders.keySet().removeIf(existing -> existing.equalsIgnoreCase(name))) {
                updatedAt = Instant.now();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Replace the entire watched headers list (called from UI on start).
     */
    public void setWatchedHeaders(java.util.List<String> headerNames) {
        lock.writeLock().lock();
        try {
            watchedHeaders.clear();
            for (String name : headerNames) {
                addWatchedHeader(name);
            }
            if (customHeaders.keySet().removeIf(name -> !isWatchedHeader(name))) {
                updatedAt = Instant.now();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get all header names being watched.
     */
    public java.util.Set<String> getWatchedHeaders() {
        lock.readLock().lock();
        try {
            return Collections.unmodifiableSet(new LinkedHashSet<>(watchedHeaders.keySet()));
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns true if the given header name is being watched.
     */
    public boolean isWatchedHeader(String headerName) {
        lock.readLock().lock();
        try {
            for (String watched : watchedHeaders.keySet()) {
                if (watched.equalsIgnoreCase(headerName)) return true;
            }
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    // --- Atomic snapshot / batch apply ---
    //
    // Some apps bind a cookie and a header together (a session-binding header, a nonce tied
    // to a specific cookie, etc.) — if the two are ever read or written a moment apart, a
    // request can go out with a fresh cookie paired with a stale header (or vice versa), which
    // looks like nothing's wrong but fails auth. Snapshot/applyCapturedResponse read or write
    // every field under a single lock acquisition so that never happens.

    /**
     * Immutable, consistent view of everything needed to build one outgoing request.
     */
    public static final class Snapshot {
        public final String cookieString;
        public final String jwt;
        public final String csrfHeaderName;
        public final String csrfValue;
        public final Map<String, String> customHeaders;

        private Snapshot(String cookieString, String jwt, String csrfHeaderName,
                          String csrfValue, Map<String, String> customHeaders) {
            this.cookieString = cookieString;
            this.jwt = jwt;
            this.csrfHeaderName = csrfHeaderName;
            this.csrfValue = csrfValue;
            this.customHeaders = customHeaders;
        }
    }

    /**
     * Read a consistent snapshot for local inspection. Request injection must use
     * getSnapshotForUrl so scope and credentials are read together.
     */
    public Snapshot getSnapshot() {
        lock.readLock().lock();
        try {
            return snapshotUnderLock(null);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Return credentials only if url matches the same scope under which they were read.
     * Returns null for an invalid/out-of-scope URL or an empty scope. The scope check and
     * immutable snapshot share one read lock, preventing a target change between them.
     */
    public Snapshot getSnapshotForUrl(String url) {
        lock.readLock().lock();
        try {
            return ScopeMatcher.matchesUrl(url, target) ? snapshotUnderLock(URI.create(url)) : null;
        } finally {
            lock.readLock().unlock();
        }
    }

    private Snapshot snapshotUnderLock(URI destination) {
        return new Snapshot(buildCookieString(destination), jwt, csrfHeaderName, csrfValue,
                Collections.unmodifiableMap(new LinkedHashMap<>(customHeaders)));
    }

    /**
     * Commit ordinary captured traffic only while its source still matches the local scope.
     * Returns false, without changing any state, when the source is no longer eligible.
     * A true result means at least one change was processed.
     */
    public boolean applyCapturedResponseForUrl(String sourceUrl, List<String> cookieHeaders,
                                                String newJwt, String newCsrfValue,
                                                Map<String, String> newCustomHeaders) {
        lock.writeLock().lock();
        try {
            if (!ScopeMatcher.matchesUrl(sourceUrl, target)) return false;
            return applyCapturedResponse(URI.create(sourceUrl), cookieHeaders, newJwt, newCsrfValue, newCustomHeaders);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Commit an explicitly configured login exchange only if its original target is still
     * selected. Unlike ordinary traffic, the login/SSO host may be outside that target.
     * Returns false without changing state if the target changed or was not configured.
     */
    public boolean applyLoginResponseForTarget(String expectedTarget, String sourceUrl, List<String> cookieHeaders,
                                                String newJwt, String newCsrfValue,
                                                Map<String, String> newCustomHeaders) {
        lock.writeLock().lock();
        try {
            if (expectedTarget == null || expectedTarget.isBlank() || !target.equals(expectedTarget)) return false;
            URI source = URI.create(sourceUrl);
            // An identity provider may issue an application token alongside its own login cookie.
            // Only application cookies belong in the shared snapshot.
            return applyCapturedResponse(source, ScopeMatcher.matchesHost(source.getHost(), target) ? cookieHeaders : List.of(),
                    newJwt, newCsrfValue, newCustomHeaders);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Atomically apply everything captured from a single response/exchange. New cookies and
     * custom headers are merged into the existing sets; JWT/CSRF are overwritten only if a new
     * value was actually found in this exchange. All under one write-lock acquisition, so a
     * concurrent reader (a follower's poll response, or a request being built for injection)
     * never observes a partial update — either the whole batch from this exchange is visible, or
     * none of it is.
     */
    private boolean applyCapturedResponse(URI source, List<String> cookieHeaders, String newJwt,
                                          String newCsrfValue, Map<String, String> newCustomHeaders) {
        Instant now = Instant.now();
        long seconds = now.getEpochSecond();
        cookies.values().removeIf(cookie -> cookie.expiresAt() <= seconds);
        boolean hasCookies = false;
        for (String header : cookieHeaders) {
            StoredCookie cookie = SetCookieParser.parse(header, source, target, now);
            if (cookie == null) continue;
            StoredCookie previous = cookies.get(cookie.key());
            if (previous != null && previous.secure() && !"https".equalsIgnoreCase(source.getScheme())) continue;
            if (cookie.expiresAt() <= seconds) cookies.remove(cookie.key());
            else cookies.put(cookie.key(), cookie);
            hasCookies = true;
        }
        boolean hasJwt = newJwt != null && !newJwt.isEmpty();
        boolean hasCsrf = newCsrfValue != null && !newCsrfValue.isEmpty();
        boolean hasCustomHeaders = newCustomHeaders != null && !newCustomHeaders.isEmpty();
        if (!hasCookies && !hasJwt && !hasCsrf && !hasCustomHeaders) return false;

        if (hasJwt) this.jwt = newJwt;
        if (hasCsrf) this.csrfValue = newCsrfValue;
        if (hasCustomHeaders) {
            for (Map.Entry<String, String> header : newCustomHeaders.entrySet()) {
                // A capture that began before a watch was removed must not restore it.
                if (isWatchedHeader(header.getKey())) {
                    customHeaders.keySet().removeIf(name -> name.equalsIgnoreCase(header.getKey()));
                    customHeaders.put(header.getKey(), header.getValue());
                }
            }
        }
        updatedAt = now;
        return true;
    }

    // --- Timestamp ---

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    // --- Serialization ---

    /**
     * Serialize the entire token store to JSON for the /tokens API endpoint.
     */
    public String toJson() {
        lock.readLock().lock();
        try {
            TokenPayload payload = new TokenPayload();
            payload.target = this.target;
            long now = Instant.now().getEpochSecond();
            payload.cookies = cookies.values().stream().filter(cookie -> cookie.expiresAt() > now).toList();
            payload.jwt = this.jwt;
            payload.csrfHeaderName = this.csrfHeaderName;
            payload.csrfValue = this.csrfValue;
            payload.customHeaders = new ConcurrentHashMap<>(this.customHeaders);
            payload.updatedAt = this.updatedAt.toString();
            return GSON.toJson(payload);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Deserialize JSON from the leader's /tokens endpoint and update this store.
     */
    public void fromJson(String json) {
        // Parse and validate before changing any live state. The endpoint sends a full
        // snapshot; missing core fields must not silently keep unrelated old credentials.
        JsonElement document = JsonParser.parseString(json);
        if (!document.isJsonObject()) {
            throw new IllegalArgumentException("Token response must be a JSON object");
        }
        JsonObject object = document.getAsJsonObject();
        lock.writeLock().lock();
        try {
            JsonElement version = object.get("version");
            if (version == null || !version.isJsonPrimitive() || !version.getAsJsonPrimitive().isString()
                    || !"2".equals(version.getAsString())) {
                clearTokens();
                throw new IllegalArgumentException("Incompatible token format. Update both peers to the same version.");
            }
            JsonElement scope = object.get("target");
            if (scope == null || !scope.isJsonPrimitive() || !scope.getAsJsonPrimitive().isString()
                    || !ScopeMatcher.equivalentScopes(target, scope.getAsString())) {
                clearTokens();
                throw new IllegalArgumentException("Target domains differ. Use the same target domains on both peers.");
            }
            String nextJwt = readString(object, "jwt");
            String nextCsrfHeader = readString(object, "csrfHeaderName");
            String nextCsrfValue = readString(object, "csrfValue");
            Map<String, String> nextCustomHeaders = readCustomHeaders(object);
            validateHeaderValue(nextJwt);
            validateHeaderValue(nextCsrfValue);
            if (!nextCsrfHeader.isEmpty()) validateName(nextCsrfHeader);
            if (nextCsrfHeader.isEmpty() && !nextCsrfValue.isEmpty()) {
                throw new IllegalArgumentException("CSRF value requires a header name");
            }

            if (object.has("updatedAt")) Instant.parse(readString(object, "updatedAt"));
            Map<CookieKey, StoredCookie> nextCookies = readCookies(object);
            cookies.clear();
            cookies.putAll(nextCookies);
            jwt = nextJwt;
            csrfHeaderName = nextCsrfHeader;
            csrfValue = nextCsrfValue;
            customHeaders.clear();
            customHeaders.putAll(nextCustomHeaders);
            this.updatedAt = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
    }

    private static Map<CookieKey, StoredCookie> readCookies(JsonObject object) {
        JsonElement entries = object.get("cookies");
        if (entries == null || !entries.isJsonArray()) {
            throw new IllegalArgumentException("Expected a list of scoped cookies");
        }
        Map<CookieKey, StoredCookie> next = new LinkedHashMap<>();
        long now = Instant.now().getEpochSecond();
        for (JsonElement entry : entries.getAsJsonArray()) {
            if (!entry.isJsonObject()) throw new IllegalArgumentException("Invalid cookie entry");
            JsonObject cookie = entry.getAsJsonObject();
            JsonElement expiresAt = cookie.get("expiresAt");
            if (expiresAt == null || !expiresAt.isJsonPrimitive() || !expiresAt.getAsJsonPrimitive().isNumber()) {
                throw new IllegalArgumentException("Missing cookie expiration");
            }
            StoredCookie parsed = new StoredCookie(readString(cookie, "name"), readString(cookie, "value"),
                    readString(cookie, "domain"), readBoolean(cookie, "hostOnly"), readString(cookie, "path"),
                    readBoolean(cookie, "secure"), Long.parseLong(expiresAt.getAsString()));
            if (parsed.expiresAt() > now) next.put(parsed.key(), parsed);
        }
        return next;
    }

    private static boolean readBoolean(JsonObject object, String name) {
        JsonElement value = object.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException("Invalid cookie field: " + name);
        }
        return value.getAsBoolean();
    }

    private static String readString(JsonObject object, String name) {
        JsonElement value = object.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("Token response field must be a string: " + name);
        }
        return value.getAsString();
    }

    private static Map<String, String> readCustomHeaders(JsonObject object) {
        JsonElement element = object.get("customHeaders");
        if (element == null) return Collections.emptyMap();
        if (!element.isJsonObject()) {
            throw new IllegalArgumentException("Expected an object of custom headers");
        }
        Map<String, String> values = new LinkedHashMap<>();
        JsonObject entries = element.getAsJsonObject();
        for (String key : entries.keySet()) {
            validateName(key);
            String value = readString(entries, key);
            validateHeaderValue(value);
            if (values.keySet().stream().anyMatch(existing -> existing.equalsIgnoreCase(key))) {
                throw new IllegalArgumentException("Duplicate custom header in token response");
            }
            values.put(key, value);
        }
        return values;
    }

    private static void validateName(String name) {
        if ("Cookie".equalsIgnoreCase(name) || "Set-Cookie".equalsIgnoreCase(name)
                || !name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) {
            throw new IllegalArgumentException("Invalid token header name in token response");
        }
    }

    private static void validateHeaderValue(String value) {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) {
                throw new IllegalArgumentException("Invalid control character in token response");
            }
        }
    }

    /**
     * Clear all stored tokens.
     */
    public void clear() {
        lock.writeLock().lock();
        try {
            clearTokens();
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void clearTokens() {
        cookies.clear();
        jwt = "";
        csrfValue = "";
        customHeaders.clear();
        updatedAt = Instant.now();
    }

    /**
     * Human-readable summary for the UI status display.
     */
    public String toDisplayString() {
        lock.readLock().lock();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("Target: ").append(target.isEmpty() ? "(not set)" : target).append("\n\n");

            sb.append("=== Cookies ===\n");
            if (cookies.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                sb.append("  ").append(buildCookieString(null)).append("\n");
            }

            sb.append("\n=== JWT ===\n");
            if (jwt == null || jwt.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                // Show truncated JWT for display
                String display = jwt.length() > 80 ? jwt.substring(0, 80) + "..." : jwt;
                sb.append("  ").append(display).append("\n");
            }

            sb.append("\n=== CSRF ===\n");
            if (csrfValue == null || csrfValue.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                sb.append("  Header: ").append(csrfHeaderName).append("\n");
                sb.append("  Value: ").append(csrfValue).append("\n");
            }

            sb.append("\n=== Custom Headers ===\n");
            if (customHeaders.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
                    sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
            }

            sb.append("\nLast Updated: ").append(updatedAt.toString()).append("\n");
            return sb.toString();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Internal payload class for JSON serialization.
     */
    private static class TokenPayload {
        String target;
        final String version = "2";
        List<StoredCookie> cookies;
        String jwt;
        String csrfHeaderName;
        String csrfValue;
        Map<String, String> customHeaders;
        String updatedAt;
    }
}
