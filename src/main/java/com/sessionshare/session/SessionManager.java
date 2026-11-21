package com.sessionshare.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sessionshare.model.TokenStore;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Session Manager — auto-refreshes session tokens when they expire.
 * Works independently of the Leader/Follower server.
 *
 * Features:
 *   1. Login Macro: user configures a login request that gets replayed to get fresh tokens
 *   2. JWT Expiry Pre-check: detects expired/expiring JWTs before requests are sent
 *   3. 401/403 Auto-refresh: triggers login macro on auth failures
 *
 * Thread-safe: uses a lock to prevent concurrent refreshes, with rate limiting.
 */
public class SessionManager {

    private final MontoyaApi api;
    private final TokenStore tokenStore;

    // Login macro configuration
    private volatile String loginUrl = "";
    private volatile String loginMethod = "POST";
    private volatile String loginContentType = "application/x-www-form-urlencoded";
    private volatile String loginBody = "";
    private volatile String loginExtraHeaders = ""; // newline-separated "Name: Value"

    // Settings
    private volatile int expiryBufferSeconds = 30; // refresh this many seconds before JWT expiry
    private volatile boolean enabled = false;

    // Prevent concurrent refreshes
    private final ReentrantLock refreshLock = new ReentrantLock();
    private volatile long lastRefreshAttemptTimeMs = 0;
    private static final long MIN_REFRESH_INTERVAL_MS = 5000; // 5 seconds between refreshes

    // Status tracking
    private volatile String lastRefreshStatus = "Not yet refreshed";
    private volatile int refreshCount = 0;

    public SessionManager(MontoyaApi api, TokenStore tokenStore) {
        this.api = api;
        this.tokenStore = tokenStore;
    }

    // ==================== Configuration getters/setters ====================

    public void setLoginUrl(String url) { this.loginUrl = url; }
    public String getLoginUrl() { return loginUrl; }

    public void setLoginMethod(String method) { this.loginMethod = method; }
    public String getLoginMethod() { return loginMethod; }

    public void setLoginContentType(String ct) { this.loginContentType = ct; }
    public String getLoginContentType() { return loginContentType; }

    public void setLoginBody(String body) { this.loginBody = body; }
    public String getLoginBody() { return loginBody; }

    public void setLoginExtraHeaders(String headers) { this.loginExtraHeaders = headers; }
    public String getLoginExtraHeaders() { return loginExtraHeaders; }

    public void setExpiryBufferSeconds(int seconds) { this.expiryBufferSeconds = seconds; }
    public int getExpiryBufferSeconds() { return expiryBufferSeconds; }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isEnabled() { return enabled; }

    public String getLastRefreshStatus() { return lastRefreshStatus; }
    public int getRefreshCount() { return refreshCount; }

    // ==================== JWT Expiry Detection ====================

    /**
     * Check if the stored JWT is expired or will expire within the buffer window.
     * Returns false if there's no JWT or no exp claim (nothing to check).
     */
    public boolean isJwtExpiredOrExpiring() {
        String jwt = tokenStore.getJwt();
        if (jwt == null || jwt.isEmpty()) return false;

        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return false;

            String payload = parts[1];
            // Base64url may need padding
            int remainder = payload.length() % 4;
            if (remainder == 2) payload += "==";
            else if (remainder == 3) payload += "=";

            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            String json = new String(decoded, StandardCharsets.UTF_8);

            JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
            if (!obj.has("exp")) return false;

            long exp = obj.get("exp").getAsLong();
            long now = Instant.now().getEpochSecond();

            return (exp - now) <= expiryBufferSeconds;
        } catch (Exception e) {
            api.logging().logToError("[SessionManager] Error checking JWT expiry: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get human-readable JWT expiry information for the UI status display.
     */
    public String getJwtExpiryInfo() {
        String jwt = tokenStore.getJwt();
        if (jwt == null || jwt.isEmpty()) return "No JWT stored";

        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return "Invalid JWT format";

            String payload = parts[1];
            int remainder = payload.length() % 4;
            if (remainder == 2) payload += "==";
            else if (remainder == 3) payload += "=";

            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            String json = new String(decoded, StandardCharsets.UTF_8);

            JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
            if (!obj.has("exp")) return "No exp claim in JWT";

            long exp = obj.get("exp").getAsLong();
            long now = Instant.now().getEpochSecond();
            long remaining = exp - now;

            if (remaining <= 0) return "EXPIRED (" + (-remaining) + "s ago)";
            return "Expires in " + remaining + "s";
        } catch (Exception e) {
            return "Error parsing JWT";
        }
    }

    // ==================== Session Refresh ====================

    /**
     * Perform a session refresh by replaying the login macro.
     * Thread-safe: only one refresh runs at a time, with rate limiting
     * to prevent flooding the server.
     *
     * @return true if refresh succeeded, false otherwise
     */
    public boolean refreshSession() {
        if (!enabled) return false;
        if (loginUrl == null || loginUrl.isEmpty()) {
            api.logging().logToOutput("[SessionManager] No login URL configured, skipping refresh");
            return false;
        }

        // Rate limit: don't refresh more than once every 5 seconds
        long now = System.currentTimeMillis();
        if ((now - lastRefreshAttemptTimeMs) < MIN_REFRESH_INTERVAL_MS) {
            api.logging().logToOutput("[SessionManager] Skipping refresh (rate limited)");
            return false;
        }

        // Only one thread refreshes at a time
        if (!refreshLock.tryLock()) {
            api.logging().logToOutput("[SessionManager] Refresh already in progress, skipping");
            return false;
        }

        try {
            lastRefreshAttemptTimeMs = System.currentTimeMillis();
            api.logging().logToOutput("[SessionManager] Refreshing session via login macro: " + loginUrl);

            String expectedTarget = tokenStore.getTarget();
            // Build the login request
            HttpRequest loginRequest = buildLoginRequest();
            if (loginRequest == null) {
                lastRefreshStatus = "Error: failed to build login request";
                return false;
            }

            // Send the request through Burp
            tokenStore.beginLoginMacro(loginUrl);
            HttpResponse response;
            try {
                response = api.http().sendRequest(loginRequest).response();
            } finally {
                tokenStore.endLoginMacro();
            }
            int statusCode = response.statusCode();
            api.logging().logToOutput("[SessionManager] Login macro response: HTTP " + statusCode);

            if (statusCode >= 200 && statusCode < 300) {
                // Success — extract tokens from response
                boolean capturedTokens = extractTokensFromResponse(response, expectedTarget, loginRequest.url());
                if (!capturedTokens) {
                    lastRefreshStatus = "Failed: login returned HTTP " + statusCode + " but no session tokens were accepted";
                    api.logging().logToError("[SessionManager] Login response had no eligible session tokens; the target may have changed");
                    return false;
                }
                refreshCount++;
                lastRefreshStatus = "OK (HTTP " + statusCode + ") at " + Instant.now();
                api.logging().logToOutput("[SessionManager] Session refreshed successfully. Total refreshes: " + refreshCount);
                return true;
            } else {
                lastRefreshStatus = "Failed (HTTP " + statusCode + ") at " + Instant.now();
                api.logging().logToError("[SessionManager] Login macro failed: HTTP " + statusCode);
                return false;
            }
        } catch (Exception e) {
            lastRefreshStatus = "Error: " + e.getMessage();
            api.logging().logToError("[SessionManager] Refresh error: " + e.getMessage());
            return false;
        } finally {
            refreshLock.unlock();
        }
    }

    // ==================== Internal helpers ====================

    /**
     * Build an HttpRequest from the login macro configuration fields.
     */
    private HttpRequest buildLoginRequest() {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(loginUrl);

            if (!"GET".equalsIgnoreCase(loginMethod)) {
                request = request.withMethod(loginMethod);

                if (loginBody != null && !loginBody.isEmpty()) {
                    request = request.withBody(loginBody);
                }

                if (loginContentType != null && !loginContentType.isEmpty()) {
                    request = request.withRemovedHeader("Content-Type")
                            .withAddedHeader("Content-Type", loginContentType);
                }
            }

            // Add extra headers (newline-separated "Name: Value" lines)
            if (loginExtraHeaders != null && !loginExtraHeaders.isEmpty()) {
                for (String line : loginExtraHeaders.split("\n")) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    int colonIdx = line.indexOf(':');
                    if (colonIdx > 0) {
                        String name = line.substring(0, colonIdx).trim();
                        String value = line.substring(colonIdx + 1).trim();
                        request = request.withRemovedHeader(name)
                                .withAddedHeader(name, value);
                    }
                }
            }

            // Inject current cookies into login request
            // (some apps require an existing session cookie for re-login)
            String cookieString = tokenStore.getCookieStringForUrl(request.url());
            return TokenRequest.withCookies(request, cookieString);
        } catch (Exception e) {
            api.logging().logToError("[SessionManager] Error building login request: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extract cookies, JWTs, and CSRF tokens from the login macro response, then apply them
     * to the token store as a single atomic batch — see TokenStore.applyCapturedResponse for why.
     */
    private boolean extractTokensFromResponse(HttpResponse response, String expectedTarget, String sourceUrl) {
        CapturedTokens tokens = CapturedTokens.read(tokenStore, response.headers(), response.bodyToString(), true);
        return tokenStore.applyLoginResponseForTarget(expectedTarget, sourceUrl, tokens.cookies(),
                tokens.jwt(), tokens.csrf(), tokens.customHeaders());
    }
}
