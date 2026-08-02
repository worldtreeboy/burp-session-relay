package com.sessionshare.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class SetCookieParserTest {
    private static final Instant NOW = Instant.parse("2026-08-02T12:00:00Z");

    @Test void preservesEqualsSignsInValues() {
        var cookie = SetCookieParser.parse("session=abc==; Path=/; Secure", NOW);
        assertEquals("session", cookie.name());
        assertEquals("abc==", cookie.value());
        assertFalse(cookie.deleted());
    }

    @Test void deletesEmptyAndMaxAgeZeroCookies() {
        assertTrue(SetCookieParser.parse("session=; Path=/", NOW).deleted());
        assertTrue(SetCookieParser.parse("session=old; Max-Age=0", NOW).deleted());
    }

    @Test void deletesExpiredCookies() {
        assertTrue(SetCookieParser.parse("session=old; Expires=Wed, 21 Oct 2015 07:28:00 GMT", NOW).deleted());
    }

    @Test void rejectsMalformedHeaders() {
        assertNull(SetCookieParser.parse("Secure; HttpOnly", NOW));
    }
}
