package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sessionshare.model.TokenStore;
import com.sessionshare.util.ScopeMatcher;

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
                Thread refreshThread = new Thread(poller::poll, "SessionShare-immediate-poll");
                refreshThread.setDaemon(true);
                refreshThread.start();
            }
        }

        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Inject cookies, JWT, and CSRF tokens into the outgoing request.
     *
     * Reads a single atomic snapshot rather than each field separately — otherwise a poll
     * update landing mid-build could pair a fresh cookie with a stale custom header (or vice
     * versa), which breaks apps that bind the two together.
     */
    private HttpRequest injectTokens(HttpRequest request) {
        HttpRequest modified = request;
        TokenStore.Snapshot snapshot = tokenStore.getSnapshot();

        // Inject cookies
        if (!snapshot.cookieString.isEmpty()) {
            modified = modified.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", snapshot.cookieString);
        }

        // Inject JWT as Bearer token
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

    /**
     * Check whether a URL matches the configured target scope.
     */
    private boolean isInScope(String url) {
        String target = tokenStore.getTarget();
        if (target == null || target.isEmpty()) return false;

        return ScopeMatcher.matchesUrl(url, target);
    }
}
