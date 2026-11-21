package com.sessionshare.session;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sessionshare.model.TokenStore;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Applies a single URL-filtered snapshot consistently across Burp handlers. */
public final class TokenRequest {
    private TokenRequest() {}

    public static HttpRequest inject(HttpRequest request, TokenStore store) {
        TokenStore.Snapshot snapshot = store.getSnapshotForUrl(request.url());
        if (snapshot == null) return request;
        HttpRequest result = withCookies(request, snapshot.cookieString);
        if (!snapshot.jwt.isEmpty()) {
            result = result.withRemovedHeader("Authorization").withAddedHeader("Authorization", "Bearer " + snapshot.jwt);
        }
        if (!snapshot.csrfHeaderName.isEmpty() && !snapshot.csrfValue.isEmpty()) {
            result = result.withRemovedHeader(snapshot.csrfHeaderName).withAddedHeader(snapshot.csrfHeaderName, snapshot.csrfValue);
        }
        for (var header : snapshot.customHeaders.entrySet()) {
            result = result.withRemovedHeader(header.getKey()).withAddedHeader(header.getKey(), header.getValue());
        }
        return result;
    }

    static HttpRequest withCookies(HttpRequest request, String captured) {
        if (captured.isEmpty()) return request;
        List<String> existing = request.headers().stream().filter(header -> "Cookie".equalsIgnoreCase(header.name()))
                .map(HttpHeader::value).toList();
        return request.withRemovedHeader("Cookie").withAddedHeader("Cookie", mergeCookies(existing, captured));
    }

    /** Preserve unrelated request cookies and all eligible same-name cookies from the store. */
    static String mergeCookies(List<String> existing, String captured) {
        Set<String> replaced = new HashSet<>();
        for (String cookie : captured.split("; ")) {
            replaced.add(cookie.substring(0, cookie.indexOf('=')));
        }
        List<String> parts = new ArrayList<>();
        parts.add(captured);
        for (String header : existing) {
            for (String item : header.split(";")) {
                String cookie = item.trim();
                int separator = cookie.indexOf('=');
                if (separator > 0 && !replaced.contains(cookie.substring(0, separator).trim())) parts.add(cookie);
            }
        }
        return String.join("; ", parts);
    }
}
