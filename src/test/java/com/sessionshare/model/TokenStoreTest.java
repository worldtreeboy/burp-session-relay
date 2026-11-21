package com.sessionshare.model;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenStoreTest {
    @Test void changingTargetClearsAllCredentialsTogether() {
        TokenStore store = populatedStore();

        store.setTarget("second.example");

        TokenStore.Snapshot snapshot = store.getSnapshot();
        assertEquals("second.example", store.getTarget());
        assertEquals("", snapshot.cookieString);
        assertEquals("", snapshot.jwt);
        assertEquals("", snapshot.csrfValue);
        assertTrue(snapshot.customHeaders.isEmpty());
    }

    @Test void unchangedTargetPreservesCredentials() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        store.setTarget("  first.example  ");

        assertEquals(before, store.toJson());
    }

    @Test void changingCsrfHeaderClearsItsOldValueButCaseChangesDoNot() {
        TokenStore store = populatedStore();

        store.setCsrfHeaderName("x-csrf-token");
        assertEquals("csrf-one", store.getCsrfValue());

        store.setCsrfHeaderName("X-New-Csrf");
        assertEquals("", store.getCsrfValue());
        assertEquals("X-New-Csrf", store.getSnapshot().csrfHeaderName);
    }

    @Test void replacingWatchListRemovesNoLongerSelectedHeadersCaseInsensitively() {
        TokenStore store = populatedStore();

        store.setWatchedHeaders(List.of("x-device"));

        assertEquals(Map.of("X-Device", "device-one"), store.getSnapshot().customHeaders);
        assertTrue(store.isWatchedHeader("X-Device"));
        assertFalse(store.isWatchedHeader("X-Session"));
    }

    @Test void removedHeaderCannotReturnFromAnAlreadyCapturedResponse() {
        TokenStore store = populatedStore();

        store.removeWatchedHeader("x-session");
        store.applyCapturedResponseForUrl("https://first.example/", List.of(), null, null, Map.of("X-SESSION", "stale"));

        assertEquals(Map.of("X-Device", "device-one"), store.getSnapshot().customHeaders);
    }

    @Test void capturesTreatHeaderNamesAsCaseInsensitive() {
        TokenStore store = populatedStore();

        store.applyCapturedResponseForUrl("https://first.example/", List.of(), null, null, Map.of("x-device", "device-two"));

        assertEquals(2, store.getSnapshot().customHeaders.size());
        assertEquals("device-two", store.getSnapshot().customHeaders.get("x-device"));
        assertFalse(store.getSnapshot().customHeaders.containsKey("X-Device"));
    }

    @Test void malformedImportCannotPartiallyReplaceExistingCredentials() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"version":"2","target":"first.example","cookies":[],"jwt":"new-jwt",
                 "csrfHeaderName":"X-CSRF-Token","csrfValue":"new-csrf",
                 "customHeaders":{"X-Device":null}}
                """));

        assertEquals(before, store.toJson());
    }

    @Test void missingOrWronglyTypedCoreFieldsCannotReportASuccessfulImport() {
        TokenStore store = populatedStore();
        String before = store.toJson();
        List<String> invalidPayloads = List.of(
                "null", "[]", "{\"version\":\"2\",\"target\":\"first.example\"}",
                "{\"version\":\"2\",\"target\":\"first.example\",\"cookies\":[],\"jwt\":42,\"csrfHeaderName\":\"\",\"csrfValue\":\"\"}",
                "{\"version\":\"2\",\"target\":\"first.example\",\"cookies\":{\"session\":null},\"jwt\":\"\",\"csrfHeaderName\":\"\",\"csrfValue\":\"\"}");

        for (String payload : invalidPayloads) {
            assertThrows(IllegalArgumentException.class, () -> store.fromJson(payload));
            assertEquals(before, store.toJson());
        }
    }

    @Test void invalidImportedHeaderValueLeavesExistingStateIntact() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"version":"2","target":"first.example","cookies":[],"jwt":"","csrfHeaderName":"","csrfValue":"",
                 "customHeaders":{"X-Device":"line one\\nline two"}}
                """));

        assertEquals(before, store.toJson());
    }

    @Test void invalidMetadataCannotCommitOtherwiseValidCredentials() {
        TokenStore store = populatedStore();
        String before = store.toJson();
        JsonObject payload = JsonParser.parseString(before).getAsJsonObject();
        payload.addProperty("jwt", "replacement");
        payload.addProperty("updatedAt", "invalid timestamp");

        assertThrows(DateTimeParseException.class, () -> store.fromJson(payload.toString()));
        assertEquals(before, store.toJson());
    }

    @Test void invalidCredentialFieldsCannotCommitAFullPayload() {
        TokenStore store = populatedStore();
        String before = store.toJson();
        List<String> invalidFields = List.of(
                "\"cookies\":{\"session\":\"one; two=three\"}",
                "\"cookies\":{\"bad name\":\"value\"}",
                "\"jwt\":\"line one\\rline two\"",
                "\"csrfHeaderName\":\"bad name\"",
                "\"csrfValue\":\"line one\\nline two\"",
                "\"customHeaders\":{\"X-Device\":\"one\",\"x-device\":\"two\"}");

        for (String fields : invalidFields) {
            JsonObject payload = JsonParser.parseString(before).getAsJsonObject();
            JsonObject invalid = JsonParser.parseString("{" + fields + "}").getAsJsonObject();
            invalid.entrySet().forEach(entry -> payload.add(entry.getKey(), entry.getValue()));
            assertThrows(IllegalArgumentException.class, () -> store.fromJson(payload.toString()));
            assertEquals(before, store.toJson());
        }
    }

    @Test void csrfValueWithoutAHeaderNameCannotCommit() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"version":"2","target":"first.example","cookies":[],"jwt":"","csrfHeaderName":"","csrfValue":"orphan"}
                """));
        assertEquals(before, store.toJson());
    }

    @Test void fullPayloadRoundTripsWithoutChangingTheFollowersLocalScope() {
        TokenStore leader = populatedStore();
        TokenStore follower = new TokenStore();
        follower.setTarget("First.Example.");

        follower.fromJson(leader.toJson());

        assertEquals("First.Example.", follower.getTarget());
        assertEquals(leader.getSnapshot().cookieString, follower.getSnapshot().cookieString);
        assertEquals(leader.getSnapshot().jwt, follower.getSnapshot().jwt);
        assertEquals(leader.getSnapshot().csrfHeaderName, follower.getSnapshot().csrfHeaderName);
        assertEquals(leader.getSnapshot().csrfValue, follower.getSnapshot().csrfValue);
        assertEquals(leader.getSnapshot().customHeaders, follower.getSnapshot().customHeaders);
    }

    @Test void legacySnapshotsAreRejectedAndStaleTokensAreCleared() {
        TokenStore store = populatedStore();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"target":"first.example","cookies":{},"jwt":"","csrfHeaderName":"","csrfValue":""}
                """));

        assertEquals("", store.getCookieString());
        assertEquals("", store.getJwt());
        assertEquals("", store.getCsrfValue());
        assertTrue(store.getSnapshot().customHeaders.isEmpty());
    }

    @Test void pooledCookiesAreWithheldFromOutOfScopeLoginDestinations() {
        TokenStore store = populatedStore();

        assertEquals("session=cookie-one", store.getCookieStringForUrl("https://first.example/login"));
        assertEquals("", store.getCookieStringForUrl("https://second.example/login"));
        assertEquals("", store.getCookieStringForUrl("https://first.example.other/login"));
        assertEquals("", store.getCookieStringForUrl("invalid URL"));

        store.setTarget("");
        assertEquals("", store.getCookieStringForUrl("https://first.example/login"));
    }

    @Test void scopedSnapshotNeverReturnsCredentialsForAnUnrelatedDestination() {
        TokenStore store = populatedStore();

        TokenStore.Snapshot first = store.getSnapshotForUrl("https://first.example/account");
        assertNotNull(first);
        assertEquals("jwt-one", first.jwt);
        assertNotNull(store.getSnapshotForUrl("https://api.first.example/account"));
        assertNull(store.getSnapshotForUrl("https://second.example/account"));
        assertNull(store.getSnapshotForUrl("invalid URL"));
        assertNull(store.getSnapshotForUrl(null));

        store.setTarget("second.example");
        store.applyCapturedResponseForUrl("https://second.example/login", List.of("session=cookie-two"),
                "jwt-two", "csrf-two", Map.of("X-Device", "device-two"));

        assertNull(store.getSnapshotForUrl("https://first.example/account"));
        TokenStore.Snapshot second = store.getSnapshotForUrl("https://second.example/account");
        assertNotNull(second);
        assertEquals("jwt-two", second.jwt);
        assertEquals("session=cookie-two", second.cookieString);
        assertEquals("jwt-one", first.jwt, "Previously returned snapshots must remain immutable");

        store.setTarget("");
        assertNull(store.getSnapshotForUrl("https://second.example/account"));
    }

    @Test void responseFromPreviousTargetCannotRestoreCredentialsAfterScopeChange() {
        TokenStore store = populatedStore();
        String originalResponseUrl = "https://first.example/login";
        store.setTarget("second.example");
        String before = store.toJson();

        boolean accepted = store.applyCapturedResponseForUrl(originalResponseUrl,
                List.of("session=stale-cookie"), "stale-jwt", "stale-csrf",
                Map.of("X-Device", "stale-device"));

        assertFalse(accepted);
        assertEquals(before, store.toJson());
    }

    @Test void scopedCaptureCommitsOneEligibleBatchAndRejectsInvalidSources() {
        TokenStore store = populatedStore();

        assertTrue(store.applyCapturedResponseForUrl("https://api.first.example/login",
                List.of("session=cookie-two"), "jwt-two", "csrf-two",
                Map.of("X-Device", "device-two")));
        TokenStore.Snapshot snapshot = store.getSnapshotForUrl("https://api.first.example/account");
        assertNotNull(snapshot);
        assertEquals("session=cookie-two", snapshot.cookieString);
        assertEquals("jwt-two", snapshot.jwt);
        assertEquals("csrf-two", snapshot.csrfValue);
        assertEquals("device-two", snapshot.customHeaders.get("X-Device"));
        String before = store.toJson();

        for (String source : new String[]{null, "invalid URL", "https://second.example/login"}) {
            assertFalse(store.applyCapturedResponseForUrl(source, List.of("session=unrelated"),
                    "unrelated", "unrelated", Map.of("X-Device", "unrelated")));
            assertEquals(before, store.toJson());
        }
    }

    @Test void configuredLoginCaptureRequiresItsOriginalTargetToRemainSelected() {
        TokenStore store = populatedStore();
        String originalTarget = store.getTarget();
        store.setTarget("second.example");
        String before = store.toJson();

        assertFalse(store.applyLoginResponseForTarget(originalTarget, "https://idp.example/login", List.of("session=stale"),
                "stale", "stale", Map.of("X-Device", "stale")));
        assertEquals(before, store.toJson());

        assertTrue(store.applyLoginResponseForTarget(store.getTarget(), "https://idp.example/login", List.of("session=current"),
                "current", "current", Map.of("X-Device", "current")));
        assertEquals("current", store.getJwt());

        store.setTarget("");
        before = store.toJson();
        assertFalse(store.applyLoginResponseForTarget("", "https://idp.example/login", List.of(), "unconfigured", null, Map.of()));
        assertEquals(before, store.toJson());
    }

    @Test void snapshotsStayImmutableWhenConfigurationChanges() {
        TokenStore store = populatedStore();
        TokenStore.Snapshot snapshot = store.getSnapshot();
        var watched = store.getWatchedHeaders();

        store.setWatchedHeaders(List.of());
        store.setTarget("second.example");

        assertEquals("session=cookie-one", snapshot.cookieString);
        assertEquals(2, snapshot.customHeaders.size());
        assertEquals(2, watched.size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.customHeaders.clear());
        assertThrows(UnsupportedOperationException.class, () -> watched.clear());
    }

    @Test void mismatchedScopeClearsStaleCredentialsWithoutChangingTheLocalTarget() {
        TokenStore follower = populatedStore();
        TokenStore leader = new TokenStore();
        leader.setTarget("other.example");
        leader.applyCapturedResponseForUrl("https://other.example/",
                List.of("session=other"), "other-token", null, Map.of());

        assertThrows(IllegalArgumentException.class, () -> follower.fromJson(leader.toJson()));
        assertEquals("first.example", follower.getTarget());
        TokenStore.Snapshot after = follower.getSnapshotForUrl("https://first.example/");
        assertEquals("", after.cookieString);
        assertEquals("", after.jwt);
        assertEquals("", after.csrfValue);
        assertTrue(after.customHeaders.isEmpty());
    }

    @Test void mismatchedScopeClearsCredentialsEvenWhenThePayloadIsAlsoMalformed() {
        TokenStore follower = populatedStore();
        assertThrows(IllegalArgumentException.class, () -> follower.fromJson("""
                {"target":"other.example","version":"2","jwt":null}
                """));
        assertEquals("", follower.getJwt());
        assertEquals("", follower.getCookieString());
    }

    @Test void cookieBoundariesAndOrderingSurviveSharingAndDeletion() {
        TokenStore leader = new TokenStore();
        leader.setTarget("example.test");
        leader.applyCapturedResponseForUrl("https://api.example.test/account/login",
                List.of("sid=root; Path=/; Secure", ";", "sid=account; Secure",
                        "team=shared; Domain=.example.test; Path=/"), null, null, Map.of());
        TokenStore follower = new TokenStore();
        follower.setTarget("example.test");
        follower.fromJson(leader.toJson());

        assertEquals("sid=account; sid=root; team=shared", follower.getCookieStringForUrl("https://api.example.test/account/me"));
        assertEquals("sid=root; team=shared", follower.getCookieStringForUrl("https://api.example.test/accountant"));
        assertEquals("team=shared", follower.getCookieStringForUrl("http://api.example.test/account/me"));
        assertEquals("team=shared", follower.getCookieStringForUrl("https://other.example.test/account/me"));
        leader.applyCapturedResponseForUrl("https://api.example.test/account/logout",
                List.of("sid=; Max-Age=0"), null, null, Map.of());
        follower.fromJson(leader.toJson());
        assertEquals("sid=root; team=shared", follower.getCookieStringForUrl("https://api.example.test/account/me"));
    }

    @Test void expiredCookiesCannotBeImportedAndMissingSecureFlagCannotDowngradeACookie() {
        TokenStore store = populatedStore();
        JsonObject object = JsonParser.parseString(store.toJson()).getAsJsonObject();
        JsonObject cookie = object.getAsJsonArray("cookies").get(0).getAsJsonObject();
        cookie.remove("secure");
        assertThrows(IllegalArgumentException.class, () -> store.fromJson(object.toString()));

        cookie.addProperty("secure", true);
        cookie.addProperty("expiresAt", 1);
        store.fromJson(object.toString());
        assertEquals("", store.getCookieString());
    }

    @Test void configuredSsoResponseKeepsHostOnlyCookiesAtTheIssuer() {
        TokenStore store = new TokenStore();
        store.setTarget("app.example");
        assertTrue(store.applyLoginResponseForTarget("app.example", "https://idp.example/login",
                List.of("idp_session=foo; Secure"), "app-access-token", null, Map.of()));
        TokenStore.Snapshot destination = store.getSnapshotForUrl("https://app.example/");
        assertEquals("", destination.cookieString);
        assertEquals("app-access-token", destination.jwt);
        assertFalse(store.toJson().contains("idp_session"));
    }

    private static TokenStore populatedStore() {
        TokenStore store = new TokenStore();
        store.setTarget("first.example");
        store.setCsrfHeaderName("X-CSRF-Token");
        store.setWatchedHeaders(List.of("X-Device", "X-Session"));
        store.applyCapturedResponseForUrl("https://first.example/", List.of("session=cookie-one"), "jwt-one", "csrf-one",
                Map.of("X-Device", "device-one", "X-Session", "session-one"));
        return store;
    }
}
