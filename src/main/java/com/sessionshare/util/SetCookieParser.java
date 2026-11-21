package com.sessionshare.util;

import java.net.URI;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.regex.Pattern;

/** Parses the attributes used to decide where and for how long a cookie can be replayed. */
public final class SetCookieParser {
    private SetCookieParser() {}

    private static final Pattern NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    public record CookieKey(String name, String domain, String path) {}

    public record StoredCookie(String name, String value, String domain, boolean hostOnly,
                               String path, boolean secure, long expiresAt) {
        public StoredCookie {
            if (name == null || !NAME.matcher(name).matches() || value == null || value.indexOf(';') >= 0
                    || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)
                    || domain == null || !validHost(domain) || path == null || !path.startsWith("/")
                    || path.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                throw new IllegalArgumentException("Invalid cookie in token response");
            }
            if ((name.startsWith("__Secure-") && !secure)
                    || (name.startsWith("__Host-") && (!secure || !hostOnly || !path.equals("/")))) {
                throw new IllegalArgumentException("Cookie does not meet its prefix restrictions");
            }
        }

        public CookieKey key() { return new CookieKey(name, domain, path); }

        public boolean matches(URI destination) {
            String host = destination.getHost().toLowerCase(Locale.ROOT);
            if (secure && !"https".equalsIgnoreCase(destination.getScheme())) return false;
            if (!host.equals(domain) && (hostOnly || !isSubdomain(host, domain))) return false;
            String requestPath = destination.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            return requestPath.equals(path) || (requestPath.startsWith(path)
                    && (path.endsWith("/") || requestPath.charAt(path.length()) == '/'));
        }
    }

    /** Returns null for invalid or unsupported cookies. Expired records identify deletions. */
    public static StoredCookie parse(String header, URI source, String target, Instant now) {
        if (header == null || source.getHost() == null) return null;
        String[] parts = header.split(";", -1);
        int equals = parts[0].indexOf('=');
        if (equals <= 0) return null;
        String name = parts[0].substring(0, equals).trim();
        String value = parts[0].substring(equals + 1).trim();
        String origin = source.getHost().toLowerCase(Locale.ROOT);
        String declaredDomain = null;
        String path = null;
        boolean secure = false;
        Long maxAge = null;
        long expires = Long.MAX_VALUE;

        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].trim();
            int split = part.indexOf('=');
            String attribute = (split < 0 ? part : part.substring(0, split)).trim().toLowerCase(Locale.ROOT);
            String content = split < 0 ? "" : part.substring(split + 1).trim();
            switch (attribute) {
                case "domain" -> declaredDomain = content.toLowerCase(Locale.ROOT);
                case "path" -> path = content;
                case "secure" -> secure = true;
                // Burp requests do not identify the browser's top-level cookie partition.
                case "partitioned" -> { return null; }
                case "max-age" -> {
                    if (content.matches("-?[0-9]+")) {
                        try { maxAge = Long.parseLong(content); }
                        catch (NumberFormatException overflow) { maxAge = content.startsWith("-") ? 0L : Long.MAX_VALUE; }
                    }
                }
                case "expires" -> {
                    // Many servers still use a dashed day-month-year and a weekday prefix.
                    String date = content.substring(content.indexOf(',') + 1).trim().replace('-', ' ');
                    try {
                        expires = ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toEpochSecond();
                    } catch (DateTimeParseException invalid) {
                        // An unreadable expiry must not turn a persistent credential into a session-long one.
                        expires = Long.MIN_VALUE;
                    }
                }
            }
        }
        if (secure && !"https".equalsIgnoreCase(source.getScheme())) return null;
        if (name.startsWith("__Host-") && (declaredDomain != null || !"/".equals(path))) return null;
        String domain = origin;
        boolean hostOnly = true;
        if (declaredDomain != null) {
            if (declaredDomain.startsWith(".")) declaredDomain = declaredDomain.substring(1);
            if (!validHost(declaredDomain) || !(origin.equals(declaredDomain) || isSubdomain(origin, declaredDomain))) {
                return null;
            }
            // A broad parent outside the configured application cannot link independent target domains.
            if (ScopeMatcher.matchesHost(declaredDomain, target)) {
                domain = declaredDomain;
                hostOnly = false;
            }
        }
        if (path == null || !path.startsWith("/")) {
            String requestPath = source.getRawPath();
            int lastSlash = requestPath == null ? -1 : requestPath.lastIndexOf('/');
            path = lastSlash <= 0 ? "/" : requestPath.substring(0, lastSlash);
        }
        if (maxAge != null) {
            long seconds = now.getEpochSecond();
            expires = maxAge <= 0 ? Long.MIN_VALUE
                    : seconds > Long.MAX_VALUE - maxAge ? Long.MAX_VALUE : seconds + maxAge;
        }
        try { return new StoredCookie(name, value, domain, hostOnly, path, secure, expires); }
        catch (IllegalArgumentException invalid) { return null; }
    }

    private static boolean validHost(String host) {
        try {
            return !host.isEmpty() && !host.endsWith(".") && host.equals(URI.create("http://" + host).getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static boolean isSubdomain(String host, String domain) {
        // IP literal cookies always require an exact host match.
        return !domain.matches("[0-9.]+") && !domain.contains(":") && host.endsWith("." + domain);
    }
}
