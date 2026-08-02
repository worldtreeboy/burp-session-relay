package com.sessionshare.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sessionshare.model.TokenStore;
import com.sessionshare.util.ScopeMatcher;

import java.util.Map;

/**
 * HTTP handler for the Session Manager feature.
 * Works independently of the Leader/Follower server.
 *
 * On every outgoing request (in scope):
 *   1. Pre-checks JWT expiry — if expired/expiring, triggers login macro BEFORE the request
 *   2. Injects latest tokens (cookies, JWT, CSRF, custom headers)
 *
 * On every incoming response (in scope):
 *   3. If 401/403 — triggers login macro so subsequent requests get fresh tokens
 *   4. Captures tokens from responses (so tokens stay updated even without Leader mode)
 */
public class SessionHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private final SessionManager sessionManager;

    public SessionHttpHandler(MontoyaApi api, TokenStore tokenStore, SessionManager sessionManager) {
        this.api = api;
        this.tokenStore = tokenStore;
        this.sessionManager = sessionManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!sessionManager.isEnabled()) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (tokenStore.shouldBypassInjection(request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        if (!isInScope(request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        // ---- Feature 2: JWT Expiry Pre-check ----
        // Before sending, check if the JWT is expired or about to expire.
        // If so, refresh the session first (blocks briefly to get fresh token).
        if (sessionManager.isJwtExpiredOrExpiring()) {
            api.logging().logToOutput("[SessionManager] JWT expired/expiring — refreshing before request to "
                    + request.url());
            sessionManager.refreshSession();
        }

        // ---- Inject latest tokens ----
        HttpRequest modified = injectTokens(request);
        return RequestToBeSentAction.continueWith(modified);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!sessionManager.isEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        String url = response.initiatingRequest().url();
        if (!isInScope(url)) {
            return ResponseReceivedAction.continueWith(response);
        }

        int statusCode = response.statusCode();

        // ---- Feature 3: 401/403 Auto-refresh ----
        // On auth failure, refresh session on a background thread so subsequent requests
        // get fresh tokens. The current response still returns as-is.
        if (statusCode == 401 || statusCode == 403) {
            api.logging().logToOutput("[SessionManager] Got HTTP " + statusCode
                    + " from " + url + " — triggering session refresh");
            Thread refreshThread = new Thread(sessionManager::refreshSession, "SessionShare-session-refresh");
            refreshThread.setDaemon(true);
            refreshThread.start();
        }

        // ---- Capture tokens from response (standalone mode support) ----
        // This lets the Session Manager capture tokens from normal browsing
        // even when Leader mode is not active.
        captureTokensFromResponse(response);

        return ResponseReceivedAction.continueWith(response);
    }

    // ==================== Token injection ====================

    /**
     * Reads a single atomic snapshot rather than each field separately, so a request never
     * mixes a fresh field with a stale one from a capture that lands mid-build.
     */
    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;
        TokenStore.Snapshot snapshot = tokenStore.getSnapshot();

        // Cookies
        if (!snapshot.cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", snapshot.cookieString);
        }

        // JWT as Bearer token
        if (snapshot.jwt != null && !snapshot.jwt.isEmpty()) {
            modified = modified.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", "Bearer " + snapshot.jwt);
        }

        // CSRF token
        if (!snapshot.csrfHeaderName.isEmpty() && !snapshot.csrfValue.isEmpty()) {
            modified = modified.withRemovedHeader(snapshot.csrfHeaderName)
                    .withAddedHeader(snapshot.csrfHeaderName, snapshot.csrfValue);
        }

        // Custom headers
        for (Map.Entry<String, String> entry : snapshot.customHeaders.entrySet()) {
            modified = modified.withRemovedHeader(entry.getKey())
                    .withAddedHeader(entry.getKey(), entry.getValue());
        }

        return modified;
    }

    // ==================== Token capture from responses ====================

    /**
     * Collects everything captured from this one response, then applies it to the token
     * store as a single atomic batch — see TokenStore.applyCapturedResponse for why.
     */
    private void captureTokensFromResponse(HttpResponseReceived response) {
        try {
            Map<String, String> capturedCookies = new java.util.LinkedHashMap<>();
            Map<String, String> capturedCustomHeaders = new java.util.LinkedHashMap<>();
            String capturedJwt = null;
            String capturedCsrf = null;

            String csrfHeader = tokenStore.getCsrfHeaderName();

            for (var header : response.headers()) {
                String name = header.name();
                String value = header.value();

                // Set-Cookie
                if ("Set-Cookie".equalsIgnoreCase(name)) {
                    String[] parts = value.split(";", 2);
                    String nameValue = parts[0].trim();
                    int eqIdx = nameValue.indexOf('=');
                    if (eqIdx > 0) {
                        capturedCookies.put(
                                nameValue.substring(0, eqIdx).trim(),
                                nameValue.substring(eqIdx + 1).trim());
                    }
                }

                // JWT from any header
                java.util.regex.Matcher jwtMatcher =
                        java.util.regex.Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
                                .matcher(value);
                if (jwtMatcher.find()) {
                    capturedJwt = jwtMatcher.group();
                }

                // CSRF header
                if (!csrfHeader.isEmpty() && csrfHeader.equalsIgnoreCase(name)) {
                    capturedCsrf = value.trim();
                }

                // Custom watched headers
                if (tokenStore.isWatchedHeader(name)) {
                    capturedCustomHeaders.put(name, value.trim());
                }
            }

            tokenStore.applyCapturedResponse(capturedCookies, capturedJwt, capturedCsrf, capturedCustomHeaders);
        } catch (Exception e) {
            api.logging().logToError("[SessionManager] Error capturing tokens from response: " + e.getMessage());
        }
    }

    // ==================== Scope check ====================

    private boolean isInScope(String url) {
        String target = tokenStore.getTarget();
        if (target == null || target.isEmpty()) return false;

        return ScopeMatcher.matchesUrl(url, target);
    }
}
