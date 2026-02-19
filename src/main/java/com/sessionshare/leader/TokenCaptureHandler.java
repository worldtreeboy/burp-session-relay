package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;

import com.sessionshare.model.TokenStore;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Leader-side handler that captures session tokens from proxied traffic.
 * Registers as both an HttpHandler (for all tool traffic) and a ProxyResponseHandler
 * (for browser proxy traffic). Extracts cookies, JWTs, and CSRF tokens from
 * responses and stores them in the shared TokenStore.
 */
public class TokenCaptureHandler implements HttpHandler, ProxyResponseHandler {

    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private volatile boolean active = false;

    // JWT regex pattern: header.payload.signature (all base64url-encoded)
    private static final Pattern JWT_PATTERN =
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    public TokenCaptureHandler(MontoyaApi api, TokenStore tokenStore) {
        this.api = api;
        this.tokenStore = tokenStore;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isActive() {
        return active;
    }

    // ==================== HttpHandler (all Burp tool traffic) ====================

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!active) {
            return RequestToBeSentAction.continueWith(request);
        }

        // Leader also auto-injects tokens into its own requests (same as followers)
        if (!isInScope(request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        HttpRequest modified = injectTokens(request);
        return RequestToBeSentAction.continueWith(modified);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!active) {
            return ResponseReceivedAction.continueWith(response);
        }

        try {
            String url = response.initiatingRequest().url();
            if (isInScope(url)) {
                extractTokensFromResponse(response.headers(), null);
            }
        } catch (Exception e) {
            api.logging().logToError("Error capturing tokens from HTTP response: " + e.getMessage());
        }

        return ResponseReceivedAction.continueWith(response);
    }

    // ==================== ProxyResponseHandler (browser proxy traffic) ====================

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {

        if (!active) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        try {
            String url = interceptedResponse.initiatingRequest().url();
            if (isInScope(url)) {
                extractTokensFromResponse(interceptedResponse.headers(),
                        interceptedResponse.bodyToString());
                api.logging().logToOutput("[Leader] Captured tokens from proxy response: " + url);
            }
        } catch (Exception e) {
            api.logging().logToError("Error capturing tokens from proxy response: " + e.getMessage());
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    // ==================== Token extraction logic ====================

    /**
     * Extract cookies, JWTs, and CSRF tokens from response headers and body.
     */
    private void extractTokensFromResponse(List<HttpHeader> headers, String body) {
        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();

            // Extract Set-Cookie headers
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                parseCookie(value);
            }

            // Extract JWT from any header value
            Matcher jwtMatcher = JWT_PATTERN.matcher(value);
            if (jwtMatcher.find()) {
                tokenStore.setJwt(jwtMatcher.group());
                api.logging().logToOutput("[Leader] Captured JWT from response header: " + name);
            }

            // Extract CSRF token from configured header
            String csrfHeader = tokenStore.getCsrfHeaderName();
            if (!csrfHeader.isEmpty() && csrfHeader.equalsIgnoreCase(name)) {
                tokenStore.setCsrfValue(value.trim());
                api.logging().logToOutput("[Leader] Captured CSRF token from header: " + csrfHeader);
            }

            // Extract custom watched headers
            if (tokenStore.isWatchedHeader(name)) {
                tokenStore.setCustomHeader(name, value.trim());
                api.logging().logToOutput("[Leader] Captured custom header: " + name);
            }
        }

        // Check response body for CSRF tokens in meta tags
        if (body != null && !body.isEmpty()) {
            extractCsrfFromBody(body);
        }
    }

    /**
     * Parse a Set-Cookie header value and store the cookie name/value pair.
     * Format: "name=value; Path=/; HttpOnly; ..."
     */
    private void parseCookie(String setCookieValue) {
        if (setCookieValue == null || setCookieValue.isEmpty()) return;

        // The cookie name=value is the first part before any ";"
        String[] parts = setCookieValue.split(";", 2);
        String nameValue = parts[0].trim();

        int equalsIndex = nameValue.indexOf('=');
        if (equalsIndex > 0) {
            String cookieName = nameValue.substring(0, equalsIndex).trim();
            String cookieValue = nameValue.substring(equalsIndex + 1).trim();
            tokenStore.setCookie(cookieName, cookieValue);
            api.logging().logToOutput("[Leader] Captured cookie: " + cookieName);
        }

        // Check if the cookie value itself is a JWT
        Matcher jwtMatcher = JWT_PATTERN.matcher(setCookieValue);
        if (jwtMatcher.find()) {
            tokenStore.setJwt(jwtMatcher.group());
            api.logging().logToOutput("[Leader] Captured JWT from Set-Cookie value");
        }
    }

    /**
     * Try to extract CSRF tokens from HTML body (meta tags, hidden inputs).
     */
    private void extractCsrfFromBody(String body) {
        String csrfHeader = tokenStore.getCsrfHeaderName();
        if (csrfHeader.isEmpty()) return;

        // Look for meta tag: <meta name="csrf-token" content="TOKEN_VALUE">
        Pattern metaPattern = Pattern.compile(
                "<meta[^>]+name=[\"'](?:csrf[_-]?token|_csrf|xsrf[_-]?token)[\"'][^>]+content=[\"']([^\"']+)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher metaMatcher = metaPattern.matcher(body);
        if (metaMatcher.find()) {
            tokenStore.setCsrfValue(metaMatcher.group(1));
            api.logging().logToOutput("[Leader] Captured CSRF token from meta tag");
            return;
        }

        // Also check reversed attribute order: content before name
        Pattern metaPattern2 = Pattern.compile(
                "<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"'](?:csrf[_-]?token|_csrf|xsrf[_-]?token)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher metaMatcher2 = metaPattern2.matcher(body);
        if (metaMatcher2.find()) {
            tokenStore.setCsrfValue(metaMatcher2.group(1));
            api.logging().logToOutput("[Leader] Captured CSRF token from meta tag (reversed)");
        }
    }

    // ==================== Token injection (leader auto-inject) ====================

    /**
     * Inject stored tokens into an outgoing request. The leader uses this too,
     * so the leader's Burp and browser stay in sync with captured tokens.
     */
    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;

        // Inject cookies
        String cookieString = tokenStore.getCookieString();
        if (!cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", cookieString);
        }

        // Inject JWT
        String jwt = tokenStore.getJwt();
        if (jwt != null && !jwt.isEmpty()) {
            modified = modified.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", "Bearer " + jwt);
        }

        // Inject CSRF token
        String csrfHeader = tokenStore.getCsrfHeaderName();
        String csrfValue = tokenStore.getCsrfValue();
        if (!csrfHeader.isEmpty() && !csrfValue.isEmpty()) {
            modified = modified.withRemovedHeader(csrfHeader)
                    .withAddedHeader(csrfHeader, csrfValue);
        }

        // Inject custom headers
        for (Map.Entry<String, String> entry : tokenStore.getCustomHeaders().entrySet()) {
            modified = modified.withRemovedHeader(entry.getKey())
                    .withAddedHeader(entry.getKey(), entry.getValue());
        }

        return modified;
    }

    // ==================== Scope check ====================

    /**
     * Check whether a URL is within the configured target scope.
     */
    private boolean isInScope(String url) {
        String target = tokenStore.getTarget();
        if (target == null || target.isEmpty()) return false;

        // Support comma-separated list of domains
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
