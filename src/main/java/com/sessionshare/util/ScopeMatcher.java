package com.sessionshare.util;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Hostname-safe matching for comma-separated target domains. */
public final class ScopeMatcher {
    private static final String IPV4_COMPONENT = "(?:[0-9]+|0[xX][0-9a-fA-F]+)";
    private static final Pattern IPV4_LITERAL = Pattern.compile(IPV4_COMPONENT + "(?:\\." + IPV4_COMPONENT + "){0,3}\\.?");

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
        String normalizedHost = normalizeHost(host.trim());
        if (normalizedHost.isEmpty()) return false;
        for (String configured : scope.split(",")) {
            String domain = normalizeEntry(configured);
            if ("*".equals(domain) || normalizedHost.equals(domain)) return true;
            if (!domain.isEmpty() && normalizedHost.endsWith("." + domain) && !isIpLiteral(domain)) return true;
        }
        return false;
    }

    /** Recognizes IPv6 and numeric IPv4 forms without resolving any hostname. */
    public static boolean isIpLiteral(String host) {
        if (host == null || host.isBlank()) return false;
        String value = host.trim();
        if (value.indexOf(':') >= 0) return !normalizeHost(value).isEmpty();
        // Count integer, abbreviated, octal and hex IPv4 forms as literals for exact-address matching.
        return IPV4_LITERAL.matcher(value).matches();
    }

    /** Compares configured target lists independent of spelling, entry order, and duplicates. */
    public static boolean equivalentScopes(String first, String second) {
        Set<String> entries = normalizedEntries(first);
        return !entries.isEmpty() && entries.equals(normalizedEntries(second));
    }

    private static Set<String> normalizedEntries(String scope) {
        if (scope == null) return Set.of();
        Set<String> entries = new HashSet<>();
        for (String configured : scope.split(",", -1)) {
            String entry = normalizeEntry(configured);
            if (entry.isEmpty()) return Set.of();
            entries.add(entry);
        }
        return entries;
    }

    private static String normalizeEntry(String configured) {
        String entry = configured.trim();
        if (entry.equals("*")) return "*";
        if (entry.startsWith("*.")) entry = entry.substring(2);
        if (entry.contains("*")) return "";
        return normalizeHost(entry);
    }

    private static String normalizeHost(String value) {
        if (value.indexOf(':') >= 0) {
            if (value.startsWith("[") && value.endsWith("]")) value = value.substring(1, value.length() - 1);
            // Zone IDs identify interfaces and must match exactly.
            int zoneStart = value.indexOf('%');
            String address = zoneStart < 0 ? value : value.substring(0, zoneStart);
            String zone = zoneStart < 0 ? "" : value.substring(zoneStart);
            try {
                // Brackets force literal parsing; hostnames never trigger a DNS lookup here.
                InetAddress literal = InetAddress.getByName("[" + address + "]");
                // Java represents an IPv4-mapped IPv6 literal as an Inet4Address.
                if (literal instanceof Inet4Address && zone.isEmpty()) return literal.getHostAddress();
                return "[" + literal.getHostAddress() + zone + "]";
            } catch (UnknownHostException ignored) {
                return "";
            }
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        return normalized;
    }
}
