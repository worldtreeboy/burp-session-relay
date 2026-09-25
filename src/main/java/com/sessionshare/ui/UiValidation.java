package com.sessionshare.ui;

import java.net.URI;

/** Validation shared by the settings form; never sends network requests. */
final class UiValidation {
    private UiValidation() {}

    static int number(String text, String label, int minimum, int maximum) {
        try {
            int value = Integer.parseInt(text.trim());
            if (value >= minimum && value <= maximum) return value;
        } catch (NumberFormatException ignored) {
        }
        throw new IllegalArgumentException(label + " must be a whole number from " + minimum + " to " + maximum + ".");
    }

    static String host(String text) {
        String host = text.trim();
        try {
            URI uri = URI.create("http://" + host);
            if (uri.getHost() != null && host.equalsIgnoreCase(uri.getHost())
                    && uri.getUserInfo() == null && uri.getPort() == -1
                    && uri.getRawPath().isEmpty() && uri.getQuery() == null && uri.getFragment() == null) {
                return host;
            }
        } catch (IllegalArgumentException ignored) {
        }
        throw new IllegalArgumentException("Enter a hostname or IP address without a URL, path, or port. Use brackets around IPv6 addresses.");
    }

    static String scope(String text) {
        String scope = text.trim();
        if (scope.isEmpty()) throw new IllegalArgumentException("Enter the target domains at the top of this tab.");
        for (String entry : scope.split(",", -1)) {
            String domain = entry.trim();
            if ("*".equals(domain)) continue;
            if (domain.startsWith("*.")) domain = domain.substring(2);
            try {
                host(domain);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Target domains must be comma-separated hostnames, such as example.com, *.internal.test. Remove URLs, paths, and ports.");
            }
        }
        return scope;
    }

    static String loginUrl(String text) {
        String value = text.trim();
        try {
            URI uri = URI.create(value);
            if (("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null && uri.getUserInfo() == null && uri.getFragment() == null
                    && (uri.getPort() == -1 || (uri.getPort() > 0 && uri.getPort() <= 65535))) return value;
        } catch (IllegalArgumentException ignored) {
        }
        throw new IllegalArgumentException("Enter a complete HTTP or HTTPS login URL without embedded credentials or a fragment.");
    }

    static String headerName(String text) {
        String name = text.trim();
        if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) {
            throw new IllegalArgumentException("Enter a valid HTTP header name, without a colon or value.");
        }
        return name;
    }
}
