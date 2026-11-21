package com.sessionshare.ui;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UiValidationTest {
    @Test void acceptsTrimmedNumbersAndBothRangeBoundaries() {
        assertEquals(1, UiValidation.number(" 1 ", "Port", 1, 65535));
        assertEquals(65535, UiValidation.number("65535", "Port", 1, 65535));
        assertEquals(30, UiValidation.number("30", "Buffer", 0, 3600));
    }

    @Test void rejectsMissingFractionalAndOutOfRangeNumbers() {
        for (String value : List.of("", " ", "0", "-1", "65536", "1.5", "text", "999999999999")) {
            assertThrows(IllegalArgumentException.class, () -> UiValidation.number(value, "Port", 1, 65535));
        }
    }

    @Test void acceptsHostnamesAndIpAddressesWithoutConnectionDetails() {
        for (String value : List.of("leader.internal.test", "localhost", "127.0.0.1", "[::1]")) {
            assertEquals(value, UiValidation.host(" " + value + " "));
        }
    }

    @Test void rejectsUrlsPortsPathsAndCredentialsInLeaderAddress() {
        for (String value : List.of("", "http://leader.test", "leader.test:8888", "leader.test/path",
                "user@leader.test", "leader.test?query", "leader.test#fragment", "::1", "bad host")) {
            assertThrows(IllegalArgumentException.class, () -> UiValidation.host(value), value);
        }
    }

    @Test void acceptsDomainListsAndRejectsMalformedEntries() {
        assertEquals("example.test, *.internal.test", UiValidation.credentialScope(" example.test, *.internal.test "));
        for (String value : List.of("", "example.test,", ",example.test", "example.test,,internal.test",
                "https://example.test", "example.test:443", "*.*.example.test", "example.test/path")) {
            assertThrows(IllegalArgumentException.class, () -> UiValidation.credentialScope(value), value);
        }
    }

    @Test void forbidsAllDestinationsForCredentialSharing() {
        assertThrows(IllegalArgumentException.class, () -> UiValidation.credentialScope("*"));
        assertThrows(IllegalArgumentException.class, () -> UiValidation.credentialScope("example.test, *"));
        assertEquals("*.example.test", UiValidation.credentialScope("*.example.test"));
    }

    @Test void acceptsOnlyCompleteHttpLoginUrlsWithValidPorts() {
        for (String value : List.of("https://example.test/login", "http://127.0.0.1:8080/login?mode=renew",
                "https://[::1]/login")) {
            assertEquals(value, UiValidation.loginUrl(" " + value + " "));
        }
        for (String value : List.of("example.test/login", "ftp://example.test/login", "https:///login",
                "https://user:password@example.test/login", "https://example.test/login#fragment",
                "https://example.test:0/login", "https://example.test:65536/login")) {
            assertThrows(IllegalArgumentException.class, () -> UiValidation.loginUrl(value), value);
        }
    }

    @Test void handlesCookiesOutsideCustomResponseHeaders() {
        assertEquals("X-Token", UiValidation.tokenHeaderName("X-Token"));
        assertThrows(IllegalArgumentException.class, () -> UiValidation.tokenHeaderName("cookie"));
        assertThrows(IllegalArgumentException.class, () -> UiValidation.tokenHeaderName("SET-COOKIE"));
        assertEquals("Cookie", UiValidation.headerName("Cookie"));
    }

    @Test void acceptsHeaderNamesButRejectsHeaderLinesAndControlCharacters() {
        assertEquals("X-CSRF-Token", UiValidation.headerName(" X-CSRF-Token "));
        for (String value : List.of("", "X Name", "X-Token: value", "X\rName", "X\nName")) {
            assertThrows(IllegalArgumentException.class, () -> UiValidation.headerName(value), value);
        }
    }
}
