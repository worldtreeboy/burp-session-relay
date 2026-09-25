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
        store.applyCapturedResponse(Map.of(), null, null, Map.of("X-SESSION", "stale"));

        assertEquals(Map.of("X-Device", "device-one"), store.getSnapshot().customHeaders);
    }

    @Test void capturesTreatHeaderNamesAsCaseInsensitive() {
        TokenStore store = populatedStore();

        store.applyCapturedResponse(Map.of(), null, null, Map.of("x-device", "device-two"));

        assertEquals(2, store.getSnapshot().customHeaders.size());
        assertEquals("device-two", store.getSnapshot().customHeaders.get("x-device"));
        assertFalse(store.getSnapshot().customHeaders.containsKey("X-Device"));
    }

    @Test void malformedImportCannotPartiallyReplaceExistingCredentials() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"cookies":{"session":"new"},"jwt":"new-jwt",
                 "csrfHeaderName":"X-CSRF-Token","csrfValue":"new-csrf",
                 "customHeaders":{"X-Device":null}}
                """));

        assertEquals(before, store.toJson());
    }

    @Test void missingOrWronglyTypedCoreFieldsCannotReportASuccessfulImport() {
        TokenStore store = populatedStore();
        String before = store.toJson();
        List<String> invalidPayloads = List.of(
                "null", "[]", "{}",
                "{\"cookies\":{},\"jwt\":42,\"csrfHeaderName\":\"\",\"csrfValue\":\"\"}",
                "{\"cookies\":{\"session\":null},\"jwt\":\"\",\"csrfHeaderName\":\"\",\"csrfValue\":\"\"}");

        for (String payload : invalidPayloads) {
            assertThrows(IllegalArgumentException.class, () -> store.fromJson(payload));
            assertEquals(before, store.toJson());
        }
    }

    @Test void invalidImportedHeaderValueLeavesExistingStateIntact() {
        TokenStore store = populatedStore();
        String before = store.toJson();

        assertThrows(IllegalArgumentException.class, () -> store.fromJson("""
                {"cookies":{},"jwt":"","csrfHeaderName":"","csrfValue":"",
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
                {"cookies":{},"jwt":"","csrfHeaderName":"","csrfValue":"orphan"}
                """));
        assertEquals(before, store.toJson());
    }

    @Test void fullPayloadRoundTripsWithoutChangingTheFollowersLocalScope() {
        TokenStore leader = populatedStore();
        TokenStore follower = new TokenStore();
        follower.setTarget("local.example");

        follower.fromJson(leader.toJson());

        assertEquals("local.example", follower.getTarget());
        assertEquals(leader.getSnapshot().cookieString, follower.getSnapshot().cookieString);
        assertEquals(leader.getSnapshot().jwt, follower.getSnapshot().jwt);
        assertEquals(leader.getSnapshot().csrfHeaderName, follower.getSnapshot().csrfHeaderName);
        assertEquals(leader.getSnapshot().csrfValue, follower.getSnapshot().csrfValue);
        assertEquals(leader.getSnapshot().customHeaders, follower.getSnapshot().customHeaders);
    }

    @Test void olderPayloadWithoutCustomHeadersReplacesAllPriorCredentials() {
        TokenStore store = populatedStore();

        store.fromJson("""
                {"cookies":{},"jwt":"","csrfHeaderName":"","csrfValue":""}
                """);

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
        store.applyCapturedResponseForUrl("https://second.example/login", Map.of("session", "cookie-two"),
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
                Map.of("session", "stale-cookie"), "stale-jwt", "stale-csrf",
                Map.of("X-Device", "stale-device"));

        assertFalse(accepted);
        assertEquals(before, store.toJson());
    }

    @Test void scopedCaptureCommitsOneEligibleBatchAndRejectsInvalidSources() {
        TokenStore store = populatedStore();

        assertTrue(store.applyCapturedResponseForUrl("https://api.first.example/login",
                Map.of("session", "cookie-two"), "jwt-two", "csrf-two",
                Map.of("X-Device", "device-two")));
        TokenStore.Snapshot snapshot = store.getSnapshotForUrl("https://first.example/account");
        assertNotNull(snapshot);
        assertEquals("session=cookie-two", snapshot.cookieString);
        assertEquals("jwt-two", snapshot.jwt);
        assertEquals("csrf-two", snapshot.csrfValue);
        assertEquals("device-two", snapshot.customHeaders.get("X-Device"));
        String before = store.toJson();

        for (String source : new String[]{null, "invalid URL", "https://second.example/login"}) {
            assertFalse(store.applyCapturedResponseForUrl(source, Map.of("session", "unrelated"),
                    "unrelated", "unrelated", Map.of("X-Device", "unrelated")));
            assertEquals(before, store.toJson());
        }
    }

    @Test void configuredLoginCaptureRequiresItsOriginalTargetToRemainSelected() {
        TokenStore store = populatedStore();
        String originalTarget = store.getTarget();
        store.setTarget("second.example");
        String before = store.toJson();

        assertFalse(store.applyLoginResponseForTarget(originalTarget, Map.of("session", "stale"),
                "stale", "stale", Map.of("X-Device", "stale")));
        assertEquals(before, store.toJson());

        assertTrue(store.applyLoginResponseForTarget(store.getTarget(), Map.of("session", "current"),
                "current", "current", Map.of("X-Device", "current")));
        assertEquals("current", store.getJwt());

        store.setTarget("");
        before = store.toJson();
        assertFalse(store.applyLoginResponseForTarget("", Map.of(), "unconfigured", null, Map.of()));
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

    private static TokenStore populatedStore() {
        TokenStore store = new TokenStore();
        store.setTarget("first.example");
        store.setCsrfHeaderName("X-CSRF-Token");
        store.setWatchedHeaders(List.of("X-Device", "X-Session"));
        store.applyCapturedResponse(Map.of("session", "cookie-one"), "jwt-one", "csrf-one",
                Map.of("X-Device", "device-one", "X-Session", "session-one"));
        return store;
    }
}
