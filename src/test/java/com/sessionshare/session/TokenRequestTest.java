package com.sessionshare.session;

import burp.api.montoya.http.message.HttpHeader;
import com.sessionshare.model.TokenStore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TokenRequestTest {
    private record Header(String name, String value) implements HttpHeader {}

    @Test void cookieJwtRetainsCookieBoundariesAcrossAllCaptureHandlers() {
        String jwt = "eyJaaaa.eyJbbbb.ccccc";
        String cookie = "session=" + jwt + "; Path=/private; Secure";
        TokenStore store = new TokenStore();
        store.addWatchedHeader("Set-Cookie");
        store.setCsrfHeaderName("Set-Cookie");
        for (boolean loginResponse : List.of(false, true)) {
            var tokens = CapturedTokens.read(store, List.of(new Header("Set-Cookie", cookie)), null, loginResponse);
            assertEquals(List.of(cookie), tokens.cookies());
            assertNull(tokens.jwt());
            assertNull(tokens.csrf());
            assertTrue(tokens.customHeaders().isEmpty());
        }
    }

    @Test void addingEligibleCookiesPreservesUnrelatedBrowserCookiesAndPathOrdering() {
        String merged = TokenRequest.mergeCookies(List.of("sid=old; theme=dark", "user_flag=one==; sid=stale"),
                "sid=account; sid=root; shared=v");
        assertEquals("sid=account; sid=root; shared=v; theme=dark; user_flag=one==", merged);
    }
}
