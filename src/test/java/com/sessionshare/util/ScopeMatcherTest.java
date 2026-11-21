package com.sessionshare.util;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

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

    @Test void supportsRouteAllWildcard() {
        assertTrue(ScopeMatcher.matchesHost("anything.example", "*"));
        assertTrue(ScopeMatcher.matchesUrl("https://unrelated.test/path", "*"));
    }

    @Test void matchesNativeSocksIpv6AndBracketedUrlToSameAddress() throws UnknownHostException {
        String scope = "example.test, [2001:db8::a]";
        byte[] address = {0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10};
        String socksHost = InetAddress.getByAddress(address).getHostAddress();
        assertTrue(ScopeMatcher.matchesHost(socksHost, scope));
        assertTrue(ScopeMatcher.matchesUrl("https://[2001:0DB8:0:0::A]:8443/path", scope));
        assertFalse(ScopeMatcher.matchesHost("2001:db8::b", scope));
        assertFalse(ScopeMatcher.matchesHost("2001:db8::a", "[2001:db8::a%1]"));
        assertFalse(ScopeMatcher.matchesHost("fe80::1%2", "[fe80::1%1]"));
        assertTrue(ScopeMatcher.matchesHost("192.0.2.1", "[::ffff:192.0.2.1]"));
        assertFalse(ScopeMatcher.matchesHost("192.0.2.2", "[::ffff:192.0.2.1]"));
    }

    @Test void identifiesNumericHostsWithoutTreatingDnsNamesAsAddresses() {
        for (String address : List.of("127.0.0.1", "127.1", "2130706433", "0177.0.0.1", "0x7f.1",
                "0x7f000001", "192.0.2.1.", "::1", "[2001:db8::1]")) {
            assertTrue(ScopeMatcher.isIpLiteral(address), address);
        }
        for (String host : List.of("localhost", "127.1.example", "api2.example", "a:b", "")) {
            assertFalse(ScopeMatcher.isIpLiteral(host), host);
        }
        assertFalse(ScopeMatcher.matchesHost("app.127.0.0.1", "127.0.0.1"));
        assertFalse(ScopeMatcher.matchesHost("app.2130706433", "2130706433"));
    }

    @Test void comparesScopeListsWithoutAcceptingMissingOrBroaderTargets() {
        assertTrue(ScopeMatcher.equivalentScopes("*.Example.test, [2001:db8::1], example.test.",
                "[2001:DB8:0:0:0:0:0:1], example.test"));
        assertFalse(ScopeMatcher.equivalentScopes("example.test", "*.test"));
        assertFalse(ScopeMatcher.equivalentScopes("example.test", "*, example.test"));
        assertFalse(ScopeMatcher.equivalentScopes("example.test", "example.test,"));
        assertFalse(ScopeMatcher.equivalentScopes("", ""));
        assertFalse(ScopeMatcher.equivalentScopes("example.test", null));
    }
}
