package com.sessionshare.util;

import java.net.URI;
import java.util.Locale;

/** Hostname-safe matching for comma-separated target domains. */
public final class ScopeMatcher {
    private ScopeMatcher() {}

    public static boolean matchesUrl(String url, String scope) {
        if (url == null) return false;
        try {
            return matchesHost(URI.create(url).getHost(), scope);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static boolean matchesHost(String host, String scope) {
        if (host == null || scope == null || scope.isBlank()) return false;
        String normalizedHost = normalize(host);
        for (String configured : scope.split(",")) {
            String domain = normalize(configured);
            if ("*".equals(domain)) return true;
            if (!domain.isEmpty()
                    && (normalizedHost.equals(domain) || normalizedHost.endsWith("." + domain))) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String value) {
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        while (normalized.startsWith("*.")) normalized = normalized.substring(2);
        while (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        return normalized;
    }
}
