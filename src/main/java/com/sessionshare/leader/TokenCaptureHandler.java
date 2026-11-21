package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;

import com.sessionshare.model.TokenStore;
import com.sessionshare.session.TokenRequest;
import com.sessionshare.session.CapturedTokens;
import com.sessionshare.util.ScopeMatcher;

import java.util.List;

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

        HttpRequest modified = TokenRequest.inject(request, tokenStore);
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
                extractTokensFromResponse(url, response.headers(), null);
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
            if (isInScope(url) && extractTokensFromResponse(url, interceptedResponse.headers(),
                    interceptedResponse.bodyToString())) {
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
    private boolean extractTokensFromResponse(String sourceUrl, List<HttpHeader> headers, String body) {
        CapturedTokens tokens = CapturedTokens.read(tokenStore, headers, body, false);
        return tokenStore.applyCapturedResponseForUrl(sourceUrl, tokens.cookies(), tokens.jwt(),
                tokens.csrf(), tokens.customHeaders());
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
