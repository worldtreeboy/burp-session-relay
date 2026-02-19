package com.sessionshare.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sessionshare.model.TokenStore;

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
            Thread.ofVirtual().start(() -> sessionManager.refreshSession());
        }

        // ---- Capture tokens from response (standalone mode support) ----
        // This lets the Session Manager capture tokens from normal browsing
        // even when Leader mode is not active.
        captureTokensFromResponse(response);

        return ResponseReceivedAction.continueWith(response);
    }

    // ==================== Token injection ====================

    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;

        // Cookies
        String cookieString = tokenStore.getCookieString();
        if (!cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", cookieString);
        }

        // JWT as Bearer token
        String jwt = tokenStore.getJwt();
        if (jwt != null && !jwt.isEmpty()) {
            modified = modified.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", "Bearer " + jwt);
        }

        // CSRF token
        String csrfHeader = tokenStore.getCsrfHeaderName();
        String csrfValue = tokenStore.getCsrfValue();
        if (csrfHeader != null && !csrfHeader.isEmpty()
                && csrfValue != null && !csrfValue.isEmpty()) {
            modified = modified.withRemovedHeader(csrfHeader)
                    .withAddedHeader(csrfHeader, csrfValue);
        }

        // Custom headers
        for (Map.Entry<String, String> entry : tokenStore.getCustomHeaders().entrySet()) {
            modified = modified.withRemovedHeader(entry.getKey())
                    .withAddedHeader(entry.getKey(), entry.getValue());
        }

        return modified;
    }

    // ==================== Token capture from responses ====================

    private void captureTokensFromResponse(HttpResponseReceived response) {
        try {
            for (var header : response.headers()) {
                String name = header.name();
                String value = header.value();

                // Set-Cookie
                if ("Set-Cookie".equalsIgnoreCase(name)) {
                    String[] parts = value.split(";", 2);
                    String nameValue = parts[0].trim();
                    int eqIdx = nameValue.indexOf('=');
                    if (eqIdx > 0) {
                        tokenStore.setCookie(
                                nameValue.substring(0, eqIdx).trim(),
                                nameValue.substring(eqIdx + 1).trim());
                    }
                }

                // JWT from any header
                java.util.regex.Matcher jwtMatcher =
                        java.util.regex.Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
                                .matcher(value);
                if (jwtMatcher.find()) {
                    tokenStore.setJwt(jwtMatcher.group());
                }

                // CSRF header
                String csrfHeader = tokenStore.getCsrfHeaderName();
                if (!csrfHeader.isEmpty() && csrfHeader.equalsIgnoreCase(name)) {
                    tokenStore.setCsrfValue(value.trim());
                }

                // Custom watched headers
                if (tokenStore.isWatchedHeader(name)) {
                    tokenStore.setCustomHeader(name, value.trim());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[SessionManager] Error capturing tokens from response: " + e.getMessage());
        }
    }

    // ==================== Scope check ====================

    private boolean isInScope(String url) {
        String target = tokenStore.getTarget();
        if (target == null || target.isEmpty()) return false;

        String[] domains = target.split(",");
        for (String domain : domains) {
            domain = domain.trim().toLowerCase();
            if (!domain.isEmpty() && url.toLowerCase().contains(domain)) {
                return true;
            }
        }
        return false;
    }
}
