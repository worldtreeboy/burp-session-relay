package com.sessionshare.util;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/** Minimal, dependency-free Set-Cookie parser for shared cookie name/value lifecycle. */
public final class SetCookieParser {
    private SetCookieParser() {}

    public static ParsedCookie parse(String headerValue, Instant now) {
        if (headerValue == null || headerValue.isBlank()) return null;
        String[] parts = headerValue.split(";");
        int equals = parts[0].indexOf('=');
        if (equals <= 0) return null;

        String name = parts[0].substring(0, equals).trim();
        String value = parts[0].substring(equals + 1).trim();
        boolean deleted = value.isEmpty();

        for (int i = 1; i < parts.length; i++) {
            String attribute = parts[i].trim();
            int attributeEquals = attribute.indexOf('=');
            String attributeName = (attributeEquals < 0 ? attribute : attribute.substring(0, attributeEquals)).trim();
            String attributeValue = attributeEquals < 0 ? "" : attribute.substring(attributeEquals + 1).trim();
            if (attributeName.equalsIgnoreCase("Max-Age")) {
                try {
                    if (Long.parseLong(attributeValue) <= 0) deleted = true;
                } catch (NumberFormatException ignored) {}
            } else if (attributeName.equalsIgnoreCase("Expires")) {
                try {
                    Instant expiry = ZonedDateTime.parse(attributeValue, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                    if (!expiry.isAfter(now)) deleted = true;
                } catch (DateTimeParseException ignored) {}
            }
        }
        return new ParsedCookie(name, deleted ? "" : value, deleted);
    }

    public record ParsedCookie(String name, String value, boolean deleted) {}
}
