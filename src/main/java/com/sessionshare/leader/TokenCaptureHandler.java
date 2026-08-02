package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;

import com.sessionshare.model.TokenStore;
import com.sessionshare.util.ScopeMatcher;
import com.sessionshare.util.SetCookieParser;
import java.time.Instant;

import java.util.LinkedHashMap;
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
        if (tokenStore.shouldBypassInjection(request.url())) {
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
     * Extract cookies, JWTs, and CSRF tokens from response headers and body, then apply them
     * to the token store as a single atomic batch — see TokenStore.applyCapturedResponse for why.
     */
    private void extractTokensFromResponse(List<HttpHeader> headers, String body) {
        Map<String, String> capturedCookies = new LinkedHashMap<>();
        Map<String, String> capturedCustomHeaders = new LinkedHashMap<>();
        String capturedJwt = null;
        String capturedCsrf = null;

        String csrfHeader = tokenStore.getCsrfHeaderName();

        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();

            // Extract Set-Cookie headers
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                String cookieJwt = parseCookie(value, capturedCookies);
                if (cookieJwt != null) capturedJwt = cookieJwt;
            }

            // Extract JWT from any header value
            Matcher jwtMatcher = JWT_PATTERN.matcher(value);
            if (jwtMatcher.find()) {
                capturedJwt = jwtMatcher.group();
                api.logging().logToOutput("[Leader] Captured JWT from response header: " + name);
            }

            // Extract CSRF token from configured header
            if (!csrfHeader.isEmpty() && csrfHeader.equalsIgnoreCase(name)) {
                capturedCsrf = value.trim();
                api.logging().logToOutput("[Leader] Captured CSRF token from header: " + csrfHeader);
            }

            // Extract custom watched headers
            if (tokenStore.isWatchedHeader(name)) {
                capturedCustomHeaders.put(name, value.trim());
                api.logging().logToOutput("[Leader] Captured custom header: " + name);
            }
        }

        // Check response body for CSRF tokens in meta tags
        if (body != null && !body.isEmpty()) {
            String bodyCsrf = extractCsrfFromBody(body, csrfHeader);
            if (bodyCsrf != null) capturedCsrf = bodyCsrf;
        }

        tokenStore.applyCapturedResponse(capturedCookies, capturedJwt, capturedCsrf, capturedCustomHeaders);
    }

    /**
     * Parse a Set-Cookie header value ("name=value; Path=/; HttpOnly; ...") into the given map.
     * Returns an embedded JWT if the cookie value itself looks like one, else null.
     */
    private String parseCookie(String setCookieValue, Map<String, String> capturedCookies) {
        if (setCookieValue == null || setCookieValue.isEmpty()) return null;

        // The cookie name=value is the first part before any ";"
        SetCookieParser.ParsedCookie cookie = SetCookieParser.parse(setCookieValue, Instant.now());
        if (cookie != null) {
            capturedCookies.put(cookie.name(), cookie.value());
            api.logging().logToOutput("[Leader] " + (cookie.deleted() ? "Deleted" : "Captured")
                    + " cookie: " + cookie.name());
        }

        // Check if the cookie value itself is a JWT
        Matcher jwtMatcher = JWT_PATTERN.matcher(setCookieValue);
        if (jwtMatcher.find()) {
            api.logging().logToOutput("[Leader] Captured JWT from Set-Cookie value");
            return jwtMatcher.group();
        }
        return null;
    }

    /**
     * Try to extract a CSRF token from HTML body (meta tags). Returns null if not found
     * or if no CSRF header name is configured.
     */
    private String extractCsrfFromBody(String body, String csrfHeader) {
        if (csrfHeader.isEmpty()) return null;

        // Look for meta tag: <meta name="csrf-token" content="TOKEN_VALUE">
        Pattern metaPattern = Pattern.compile(
                "<meta[^>]+name=[\"'](?:csrf[_-]?token|_csrf|xsrf[_-]?token)[\"'][^>]+content=[\"']([^\"']+)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher metaMatcher = metaPattern.matcher(body);
        if (metaMatcher.find()) {
            api.logging().logToOutput("[Leader] Captured CSRF token from meta tag");
            return metaMatcher.group(1);
        }

        // Also check reversed attribute order: content before name
        Pattern metaPattern2 = Pattern.compile(
                "<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"'](?:csrf[_-]?token|_csrf|xsrf[_-]?token)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher metaMatcher2 = metaPattern2.matcher(body);
        if (metaMatcher2.find()) {
            api.logging().logToOutput("[Leader] Captured CSRF token from meta tag (reversed)");
            return metaMatcher2.group(1);
        }
        return null;
    }

    // ==================== Token injection (leader auto-inject) ====================

    /**
     * Inject stored tokens into an outgoing request. The leader uses this too,
     * so the leader's Burp and browser stay in sync with captured tokens.
     *
     * Reads a single atomic snapshot rather than each field separately, so a request never
     * mixes a fresh field with a stale one from a capture that lands mid-build.
     */
    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;
        TokenStore.Snapshot snapshot = tokenStore.getSnapshot();

        // Inject cookies
        if (!snapshot.cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", snapshot.cookieString);
        }

        // Inject JWT
        if (snapshot.jwt != null && !snapshot.jwt.isEmpty()) {
            modified = modified.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", "Bearer " + snapshot.jwt);
        }

        // Inject CSRF token
        if (!snapshot.csrfHeaderName.isEmpty() && !snapshot.csrfValue.isEmpty()) {
            modified = modified.withRemovedHeader(snapshot.csrfHeaderName)
                    .withAddedHeader(snapshot.csrfHeaderName, snapshot.csrfValue);
        }

        // Inject custom headers
        for (Map.Entry<String, String> entry : snapshot.customHeaders.entrySet()) {
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

        return ScopeMatcher.matchesUrl(url, target);
    }
}
