package com.sessionshare.util;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class SetCookieParserTest {
    private static final Instant NOW = Instant.parse("2026-08-02T12:00:00Z");
    private static final URI SOURCE = URI.create("https://api.example.test/login/start");

    private static SetCookieParser.StoredCookie parse(String header) {
        return SetCookieParser.parse(header, SOURCE, "example.test", NOW);
    }

    @Test void preservesEqualsAndEmptyValues() {
        assertEquals("abc==", parse("session=abc==; Path=/; Secure").value());
        assertEquals("", parse("session=; Path=/").value());
    }

    @Test void zeroMaxAgeDeletesEvenWithFutureExpiry() {
        assertTrue(parse("session=old; Max-Age=0; Expires=Thu, 21 Oct 2032 07:28:00 GMT").expiresAt() <= NOW.getEpochSecond());
    }

    @Test void invalidMaxAgeFallsBackToExpires() {
        for (String expires : new String[]{"Wed, 21 Oct 2015 07:28:00 GMT", "Wed, 21-Oct-2015 07:28:00 GMT", "unreadable"}) {
            assertTrue(parse("session=old; Max-Age=invalid; Expires=" + expires).expiresAt() <= NOW.getEpochSecond());
        }
    }

    @Test void validMaxAgeOverridesExpiredDateInEitherOrder() {
        String expired = "Expires=Wed, 21 Oct 2015 07:28:00 GMT";
        for (String attributes : new String[]{"Max-Age=60; " + expired, expired + "; Max-Age=60"}) {
            assertEquals(NOW.getEpochSecond() + 60, parse("session=current; " + attributes).expiresAt());
        }
    }

    @Test void rejectsMalformedCookieNamesAndUnrelatedDomains() {
        assertNull(parse(";"));
        assertNull(parse(";;;"));
        assertNull(parse("Secure; HttpOnly"));
        assertNull(parse("   =value; Path=/"));
        assertNull(parse("bad name=value"));
        assertNull(parse("a=1; Domain=unrelated.test"));
    }

    @Test void defaultsToOriginAndDirectoryWithPathBoundaries() {
        var cookie = parse("sid=x; Secure");
        assertTrue(cookie.matches(URI.create("https://api.example.test/login")));
        assertTrue(cookie.matches(URI.create("https://api.example.test/login/finish")));
        assertFalse(cookie.matches(URI.create("https://api.example.test/logins")));
        assertFalse(cookie.matches(URI.create("http://api.example.test/login/finish")));
        assertFalse(cookie.matches(URI.create("https://other.example.test/login/finish")));
    }

    @Test void doesNotWidenCookiesPastTheConfiguredDomainOrUnsupportedBrowserPartition() {
        var cookie = parse("sid=x; Domain=test; Path=/");
        assertTrue(cookie.hostOnly());
        assertFalse(cookie.matches(URI.create("https://other.example.test/")));
        assertNull(parse("sid=x; Secure; Partitioned"));
        assertNull(parse("__Host-id=x; Domain=api.example.test; Path=/; Secure"));
        assertNull(parse("__Secure-id=x"));
    }
}
