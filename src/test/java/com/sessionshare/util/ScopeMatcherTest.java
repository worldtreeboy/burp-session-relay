package com.sessionshare.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScopeMatcherTest {
    @Test void matchesExactAndSubdomain() {
        assertTrue(ScopeMatcher.matchesHost("example.com", "example.com"));
        assertTrue(ScopeMatcher.matchesHost("api.example.com", "example.com"));
    }

    @Test void supportsWildcardsAndMultipleDomains() {
        String scope = "*.internal.example.com, partner.test";
        assertTrue(ScopeMatcher.matchesHost("internal.example.com", scope));
        assertTrue(ScopeMatcher.matchesHost("api.internal.example.com", scope));
        assertTrue(ScopeMatcher.matchesHost("partner.test", scope));
    }

    @Test void rejectsLookalikeHostsAndUrlText() {
        assertFalse(ScopeMatcher.matchesHost("example.com.attacker.test", "example.com"));
        assertFalse(ScopeMatcher.matchesUrl("https://attacker.test/path/example.com?q=example.com", "example.com"));
    }

    @Test void handlesCaseAndTrailingDot() {
        assertTrue(ScopeMatcher.matchesHost("API.EXAMPLE.COM.", "*.Example.Com."));
    }
}
