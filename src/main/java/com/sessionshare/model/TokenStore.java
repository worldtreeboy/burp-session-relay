package com.sessionshare.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.time.Instant;
import java.util.Collections;
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
    private final ConcurrentHashMap<String, String> cookies = new ConcurrentHashMap<>();
    private volatile String jwt = "";
    private volatile String csrfHeaderName = "";
    private volatile String csrfValue = "";
    private volatile String target = "";
    private volatile Instant updatedAt = Instant.now();

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
        this.target = target;
    }

    // --- Cookies ---

    /**
     * Build a Cookie header string: "name1=value1; name2=value2"
     */
    public String getCookieString() {
        lock.readLock().lock();
        try {
            return buildCookieString();
        } finally {
            lock.readLock().unlock();
        }
    }

    private String buildCookieString() {
        if (cookies.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
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
        this.csrfHeaderName = csrfHeaderName;
    }

    public String getCsrfValue() {
        return csrfValue;
    }

    // --- Custom Headers ---

    /**
     * Add a header name to watch for in responses (leader-side config).
     */
    public void addWatchedHeader(String headerName) {
        watchedHeaders.put(headerName, Boolean.TRUE);
    }

    /**
     * Remove a header name from the watch list.
     */
    public void removeWatchedHeader(String headerName) {
        watchedHeaders.remove(headerName);
        customHeaders.remove(headerName);
    }

    /**
     * Replace the entire watched headers list (called from UI on start).
     */
    public void setWatchedHeaders(java.util.List<String> headerNames) {
        watchedHeaders.clear();
        for (String name : headerNames) {
            if (name != null && !name.trim().isEmpty()) {
                watchedHeaders.put(name.trim(), Boolean.TRUE);
            }
        }
    }

    /**
     * Get all header names being watched.
     */
    public java.util.Set<String> getWatchedHeaders() {
        return Collections.unmodifiableSet(watchedHeaders.keySet());
    }

    /**
     * Returns true if the given header name is being watched.
     */
    public boolean isWatchedHeader(String headerName) {
        for (String watched : watchedHeaders.keySet()) {
            if (watched.equalsIgnoreCase(headerName)) return true;
        }
        return false;
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
     * Read every field needed for request injection in one atomic snapshot.
     */
    public Snapshot getSnapshot() {
        lock.readLock().lock();
        try {
            return new Snapshot(
                    buildCookieString(),
                    jwt,
                    csrfHeaderName,
                    csrfValue,
                    Collections.unmodifiableMap(new java.util.LinkedHashMap<>(customHeaders)));
        } finally {
            lock.readLock().unlock();
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
    public void applyCapturedResponse(Map<String, String> newCookies, String newJwt,
                                       String newCsrfValue, Map<String, String> newCustomHeaders) {
        boolean hasCookies = newCookies != null && !newCookies.isEmpty();
        boolean hasJwt = newJwt != null && !newJwt.isEmpty();
        boolean hasCsrf = newCsrfValue != null && !newCsrfValue.isEmpty();
        boolean hasCustomHeaders = newCustomHeaders != null && !newCustomHeaders.isEmpty();

        if (!hasCookies && !hasJwt && !hasCsrf && !hasCustomHeaders) {
            return;
        }

        lock.writeLock().lock();
        try {
            if (hasCookies) cookies.putAll(newCookies);
            if (hasJwt) this.jwt = newJwt;
            if (hasCsrf) this.csrfValue = newCsrfValue;
            if (hasCustomHeaders) customHeaders.putAll(newCustomHeaders);
            updatedAt = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
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
            payload.cookies = new ConcurrentHashMap<>(this.cookies);
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
        lock.writeLock().lock();
        try {
            TokenPayload payload = GSON.fromJson(json, TokenPayload.class);
            if (payload == null) return;

            // Scope is a local security boundary. Never let a remote leader change where
            // this follower injects credentials.
            if (payload.cookies != null) {
                this.cookies.clear();
                this.cookies.putAll(payload.cookies);
            }
            if (payload.jwt != null) this.jwt = payload.jwt;
            if (payload.csrfHeaderName != null) this.csrfHeaderName = payload.csrfHeaderName;
            if (payload.csrfValue != null) this.csrfValue = payload.csrfValue;
            if (payload.customHeaders != null) {
                this.customHeaders.clear();
                this.customHeaders.putAll(payload.customHeaders);
            }
            this.updatedAt = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Clear all stored tokens.
     */
    public void clear() {
        lock.writeLock().lock();
        try {
            cookies.clear();
            jwt = "";
            csrfValue = "";
            customHeaders.clear();
            updatedAt = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
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
                for (Map.Entry<String, String> entry : cookies.entrySet()) {
                    sb.append("  ").append(entry.getKey()).append(" = ").append(entry.getValue()).append("\n");
                }
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
        Map<String, String> cookies;
        String jwt;
        String csrfHeaderName;
        String csrfValue;
        Map<String, String> customHeaders;
        String updatedAt;
    }
}
