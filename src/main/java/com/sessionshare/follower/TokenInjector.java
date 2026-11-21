package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.sessionshare.model.TokenStore;
import com.sessionshare.session.TokenRequest;
import com.sessionshare.util.ScopeMatcher;

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
        if (tokenStore.shouldBypassInjection(request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        // Only inject into requests that match the target scope
        if (!isInScope(request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        HttpRequest modified = TokenRequest.inject(request, tokenStore);
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
     * Check whether a URL matches the configured target scope.
     */
    private boolean isInScope(String url) {
        String target = tokenStore.getTarget();
        if (target == null || target.isEmpty()) return false;

        return ScopeMatcher.matchesUrl(url, target);
    }
}
