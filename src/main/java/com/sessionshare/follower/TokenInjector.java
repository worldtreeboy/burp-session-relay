package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sessionshare.model.TokenStore;

import java.util.Map;

/**
 * Follower-side HTTP handler that injects the latest tokens (fetched from the leader)
 * into every outgoing HTTP request that matches the configured target scope.
 */
public class TokenInjector implements HttpHandler {

    private final MontoyaApi api;
    private final TokenStore tokenStore;
    private final TokenPoller poller;
    private volatile boolean active = false;

    public TokenInjector(MontoyaApi api, TokenStore tokenStore, TokenPoller poller) {
        this.api = api;
        this.tokenStore = tokenStore;
        this.poller = poller;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isActive() {
        return active;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!active) {
            return RequestToBeSentAction.continueWith(request);
        }

        // Only inject into requests that match the target scope
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

        // If we get a 401 or 403, immediately re-fetch tokens from the leader
        int statusCode = response.statusCode();
        if (statusCode == 401 || statusCode == 403) {
            if (isInScope(response.initiatingRequest().url())) {
                api.logging().logToOutput("[Follower] Got " + statusCode
                        + " — triggering immediate token refresh");
                // Run the poll on a background thread to avoid blocking Burp
                Thread.ofVirtual().start(() -> poller.poll());
            }
        }

        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Inject cookies, JWT, and CSRF tokens into the outgoing request.
     */
    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;

        // Inject cookies
        String cookieString = tokenStore.getCookieString();
        if (!cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", cookieString);
        }

        // Inject JWT as Bearer token
        String jwt = tokenStore.getJwt();
        if (jwt != null && !jwt.isEmpty()) {
            modified = modified.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", "Bearer " + jwt);
        }

        // Inject CSRF token
        String csrfHeader = tokenStore.getCsrfHeaderName();
        String csrfValue = tokenStore.getCsrfValue();
        if (csrfHeader != null && !csrfHeader.isEmpty()
                && csrfValue != null && !csrfValue.isEmpty()) {
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

    /**
     * Check whether a URL matches the configured target scope.
     */
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
