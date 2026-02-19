package com.sessionshare.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import burp.api.montoya.core.ByteArray;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JWT scan check — passive analysis + active alg:none attack.
 *
 * Passive: flags alg:none, HS256, missing expiry, expired tokens accepted, sensitive data.
 * Active: takes a JWT from the insertion point, forges it with alg:none and empty signature,
 *         sends it, and confirms whether the server accepts the forged token.
 */
public class JwtPassiveScanCheck implements ScanCheck {

    private final MontoyaApi api;

    private static final Pattern JWT_PATTERN =
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    private static final Set<String> SENSITIVE_FIELDS = Set.of(
            "password", "passwd", "pass", "secret", "ssn",
            "social_security", "credit_card", "creditcard", "cc_number",
            "card_number", "cvv", "pin", "private_key", "privatekey"
    );

    public JwtPassiveScanCheck(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        try {
            // Collect all JWTs from both request and response
            Set<String> jwts = new HashSet<>();

            // Check request headers
            for (HttpHeader header : baseRequestResponse.request().headers()) {
                findJwts(header.value(), jwts);
            }

            // Check response headers
            for (HttpHeader header : baseRequestResponse.response().headers()) {
                findJwts(header.value(), jwts);
            }

            // Check response body
            String responseBody = baseRequestResponse.response().bodyToString();
            if (responseBody != null) {
                findJwts(responseBody, jwts);
            }

            // Analyze each JWT found
            for (String jwt : jwts) {
                issues.addAll(analyzeJwt(jwt, baseRequestResponse));
            }
        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error during passive audit: " + e.getMessage());
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        try {
            String baseValue = insertionPoint.baseValue();
            if (baseValue == null || baseValue.isEmpty()) {
                return AuditResult.auditResult();
            }

            // Check if the insertion point value contains a JWT
            Matcher matcher = JWT_PATTERN.matcher(baseValue);
            if (!matcher.find()) {
                return AuditResult.auditResult();
            }

            String originalJwt = matcher.group();
            String[] parts = originalJwt.split("\\.");
            if (parts.length < 3) {
                return AuditResult.auditResult();
            }

            String url = baseRequestResponse.request().url();
            String jwtPreview = originalJwt.substring(0, Math.min(80, originalJwt.length())) + "...";

            // --- Attack 1: alg:none bypass ---
            String algNoneJwt = forgeAlgNone(parts[0], parts[1]);
            if (algNoneJwt != null) {
                AuditIssue issue = sendAndCheck(insertionPoint, baseValue, originalJwt, algNoneJwt,
                        "JWT Algorithm None Bypass Confirmed",
                        "The server accepted a JWT with the algorithm changed to \"none\" and the "
                                + "signature stripped. An attacker can forge arbitrary tokens without "
                                + "knowing the signing key."
                                + "\n\nOriginal: " + jwtPreview
                                + "\nForged: " + algNoneJwt,
                        "Reject JWTs with algorithm \"none\". Whitelist allowed algorithms server-side.",
                        url, baseRequestResponse);
                if (issue != null) {
                    issues.add(issue);
                    api.logging().logToOutput("[JWT Scanner] CONFIRMED: alg:none bypass on " + url);
                }
            }

            // --- Attack 2: Empty signature (keep original alg) ---
            String emptySigJwt = parts[0] + "." + parts[1] + ".";
            {
                AuditIssue issue = sendAndCheck(insertionPoint, baseValue, originalJwt, emptySigJwt,
                        "JWT Empty Signature Accepted",
                        "The server accepted a JWT with the original algorithm but an empty signature. "
                                + "This means the server is not validating JWT signatures."
                                + "\n\nOriginal: " + jwtPreview
                                + "\nForged: " + emptySigJwt,
                        "Ensure the server verifies JWT signatures and rejects tokens with missing signatures.",
                        url, baseRequestResponse);
                if (issue != null) {
                    issues.add(issue);
                    api.logging().logToOutput("[JWT Scanner] CONFIRMED: empty signature accepted on " + url);
                }
            }

            // --- Attack 3: Corrupted signature (flip bytes) ---
            String corruptedSig = corruptSignature(parts[2]);
            String corruptedJwt = parts[0] + "." + parts[1] + "." + corruptedSig;
            {
                AuditIssue issue = sendAndCheck(insertionPoint, baseValue, originalJwt, corruptedJwt,
                        "JWT Corrupted Signature Accepted",
                        "The server accepted a JWT with a corrupted signature. "
                                + "This means the server is not properly verifying JWT signature integrity."
                                + "\n\nOriginal: " + jwtPreview
                                + "\nForged (corrupted sig): " + corruptedJwt.substring(0, Math.min(80, corruptedJwt.length())) + "...",
                        "Ensure the server performs full cryptographic signature verification on every JWT.",
                        url, baseRequestResponse);
                if (issue != null) {
                    issues.add(issue);
                    api.logging().logToOutput("[JWT Scanner] CONFIRMED: corrupted signature accepted on " + url);
                }
            }

            // --- Attack 4: Remove exp claim ---
            String noExpJwt = forgeWithoutExp(parts[0], parts[1]);
            if (noExpJwt != null) {
                AuditIssue issue = sendAndCheck(insertionPoint, baseValue, originalJwt, noExpJwt,
                        "JWT Without Expiry Accepted",
                        "The server accepted a JWT with the \"exp\" claim removed. "
                                + "This means an attacker can create tokens that never expire."
                                + "\n\nOriginal: " + jwtPreview
                                + "\nForged (exp removed): " + noExpJwt.substring(0, Math.min(80, noExpJwt.length())) + "...",
                        "Ensure the server requires and validates the \"exp\" claim in every JWT.",
                        url, baseRequestResponse);
                if (issue != null) {
                    issues.add(issue);
                    api.logging().logToOutput("[JWT Scanner] CONFIRMED: JWT without exp accepted on " + url);
                }
            }

        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error during active audit: " + e.getMessage());
        }

        return AuditResult.auditResult(issues);
    }

    // ==================== Active audit helpers ====================

    /**
     * Send a tampered JWT and check if the server accepts it (2xx response).
     * Returns an AuditIssue if vulnerable, null otherwise.
     */
    private AuditIssue sendAndCheck(AuditInsertionPoint insertionPoint,
                                    String baseValue, String originalJwt, String forgedJwt,
                                    String issueName, String issueDetail, String remediation,
                                    String url, HttpRequestResponse baseReqResp) {
        try {
            String tamperedValue = baseValue.replace(originalJwt, forgedJwt);
            HttpRequestResponse response = api.http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(tamperedValue)));

            short statusCode = response.response().statusCode();
            if (statusCode >= 200 && statusCode < 300) {
                return AuditIssue.auditIssue(
                        issueName,
                        issueDetail + "\nServer response: HTTP " + statusCode,
                        null, url,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null, remediation,
                        AuditIssueSeverity.HIGH,
                        baseReqResp);
            }
        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error in sendAndCheck: " + e.getMessage());
        }
        return null;
    }

    /**
     * Forge a JWT with alg set to "none" and an empty signature.
     */
    private String forgeAlgNone(String originalHeader, String originalPayload) {
        try {
            String headerJson = new String(base64UrlDecode(originalHeader), StandardCharsets.UTF_8);
            JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
            header.addProperty("alg", "none");
            String forgedHeader = base64UrlEncode(header.toString().getBytes(StandardCharsets.UTF_8));
            return forgedHeader + "." + originalPayload + ".";
        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error forging alg:none JWT: " + e.getMessage());
            return null;
        }
    }

    /**
     * Corrupt a JWT signature by flipping characters.
     */
    private String corruptSignature(String signature) {
        if (signature == null || signature.length() < 2) return "AAAA";
        char[] chars = signature.toCharArray();
        // Flip the first few characters
        for (int i = 0; i < Math.min(4, chars.length); i++) {
            chars[i] = (chars[i] == 'A') ? 'B' : 'A';
        }
        return new String(chars);
    }

    /**
     * Forge a JWT with the "exp" claim removed from the payload.
     * Keeps the original header, strips the signature (since we modified the payload).
     */
    private String forgeWithoutExp(String originalHeader, String originalPayload) {
        try {
            String payloadJson = new String(base64UrlDecode(originalPayload), StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

            if (!payload.has("exp")) {
                // Already has no exp — skip this check
                return null;
            }

            payload.remove("exp");
            String forgedPayload = base64UrlEncode(payload.toString().getBytes(StandardCharsets.UTF_8));

            // Use alg:none since we can't re-sign the modified payload
            String headerJson = new String(base64UrlDecode(originalHeader), StandardCharsets.UTF_8);
            JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
            header.addProperty("alg", "none");
            String forgedHeader = base64UrlEncode(header.toString().getBytes(StandardCharsets.UTF_8));

            return forgedHeader + "." + forgedPayload + ".";
        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error forging no-exp JWT: " + e.getMessage());
            return null;
        }
    }

    /**
     * Base64URL encode without padding.
     */
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equals(existingIssue.name())
                && newIssue.detail().equals(existingIssue.detail())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    // ==================== JWT analysis ====================

    private void findJwts(String text, Set<String> jwts) {
        Matcher matcher = JWT_PATTERN.matcher(text);
        while (matcher.find()) {
            jwts.add(matcher.group());
        }
    }

    private List<AuditIssue> analyzeJwt(String jwt, HttpRequestResponse reqResp) {
        List<AuditIssue> issues = new ArrayList<>();

        String[] parts = jwt.split("\\.");
        if (parts.length < 2) return issues;

        try {
            // Decode header
            String headerJson = new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8);
            JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();

            // Decode payload
            String payloadJson = new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

            // Check 1: Algorithm "none"
            if (header.has("alg")) {
                String alg = header.get("alg").getAsString();
                if ("none".equalsIgnoreCase(alg)) {
                    issues.add(AuditIssue.auditIssue(
                            "JWT Algorithm None Detected",
                            "A JWT with algorithm set to \"none\" was detected. This means the token "
                                    + "has no signature verification, allowing an attacker to forge arbitrary tokens."
                                    + "\n\nJWT Header: " + headerJson,
                            null,
                            reqResp.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            "Ensure the server rejects JWTs with algorithm \"none\". "
                                    + "Use a strong algorithm like RS256 or ES256.",
                            AuditIssueSeverity.HIGH,
                            reqResp
                    ));
                }

                // Check 2: Weak algorithm HS256
                // Note: This is an informational finding. The scanner cannot verify
                // whether the secret is actually weak — that requires offline brute-force
                // (e.g., hashcat -m 16500 or jwt_tool). This flags HS256 usage so the
                // tester knows to attempt secret cracking manually.
                if ("HS256".equalsIgnoreCase(alg)) {
                    issues.add(AuditIssue.auditIssue(
                            "JWT Uses HS256 Algorithm",
                            "A JWT using HS256 (HMAC-SHA256) was detected. HS256 uses a symmetric "
                                    + "shared secret which can be brute-forced offline if weak. "
                                    + "This is an informational finding — test the secret strength manually "
                                    + "with tools like hashcat (mode 16500) or jwt_tool."
                                    + "\n\nJWT Header: " + headerJson,
                            null,
                            reqResp.request().url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            "Consider using asymmetric signing algorithms (RS256 or ES256) "
                                    + "and ensure secrets are long and random.",
                            AuditIssueSeverity.INFORMATION,
                            reqResp
                    ));
                }
            }

            // Check 3: Missing expiry claim
            if (!payload.has("exp")) {
                issues.add(AuditIssue.auditIssue(
                        "JWT Missing Expiry Claim",
                        "A JWT without an \"exp\" (expiry) claim was detected. Tokens without expiry "
                                + "never expire and can be replayed indefinitely if compromised."
                                + "\n\nJWT Payload: " + payloadJson,
                        null,
                        reqResp.request().url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        "Always include an \"exp\" claim in JWTs with a reasonable expiry time.",
                        AuditIssueSeverity.MEDIUM,
                        reqResp
                ));
            } else {
                // Check 4: Expired token still accepted by the server
                // Only flag this if the JWT was in the REQUEST (client sent it)
                // AND the server responded with a 2xx success status — meaning
                // it accepted the expired token instead of rejecting with 401/403.
                long exp = payload.get("exp").getAsLong();
                if (Instant.ofEpochSecond(exp).isBefore(Instant.now())) {
                    boolean jwtInRequest = false;
                    for (HttpHeader h : reqResp.request().headers()) {
                        if (JWT_PATTERN.matcher(h.value()).find()) {
                            jwtInRequest = true;
                            break;
                        }
                    }

                    short statusCode = reqResp.response().statusCode();
                    boolean serverAccepted = statusCode >= 200 && statusCode < 300;

                    if (jwtInRequest && serverAccepted) {
                        // Server returned 2xx for a request with an expired JWT — confirmed
                        issues.add(AuditIssue.auditIssue(
                                "Expired JWT Accepted by Server",
                                "An expired JWT was sent in the request and the server responded with "
                                        + "HTTP " + statusCode + ", confirming it accepted the expired token. "
                                        + "Expiry was: " + Instant.ofEpochSecond(exp)
                                        + "\n\nJWT Payload: " + payloadJson,
                                null,
                                reqResp.request().url(),
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.CERTAIN,
                                null,
                                "Ensure the server validates the \"exp\" claim and rejects expired tokens.",
                                AuditIssueSeverity.HIGH,
                                reqResp
                        ));
                    } else if (jwtInRequest) {
                        // Expired JWT was sent but server rejected it — not an issue, skip
                    } else {
                        // Expired JWT appeared in the response only — informational
                        issues.add(AuditIssue.auditIssue(
                                "Expired JWT in Response",
                                "The server returned a JWT with an expired \"exp\" claim. "
                                        + "Expiry was: " + Instant.ofEpochSecond(exp)
                                        + "\n\nJWT Payload: " + payloadJson,
                                null,
                                reqResp.request().url(),
                                AuditIssueSeverity.INFORMATION,
                                AuditIssueConfidence.FIRM,
                                null,
                                "Investigate why the server is issuing already-expired tokens.",
                                AuditIssueSeverity.INFORMATION,
                                reqResp
                        ));
                    }
                }
            }

            // Check 5: Sensitive data in payload
            List<String> foundSensitive = new ArrayList<>();
            for (Map.Entry<String, JsonElement> entry : payload.entrySet()) {
                if (SENSITIVE_FIELDS.contains(entry.getKey().toLowerCase())) {
                    foundSensitive.add(entry.getKey());
                }
            }
            if (!foundSensitive.isEmpty()) {
                issues.add(AuditIssue.auditIssue(
                        "JWT Contains Sensitive Data",
                        "A JWT was found containing potentially sensitive fields in its payload: "
                                + String.join(", ", foundSensitive)
                                + ". JWTs are base64-encoded (not encrypted) and can be decoded by anyone. "
                                + "Sensitive data should never be stored in JWT payloads."
                                + "\n\nJWT Payload: " + payloadJson,
                        null,
                        reqResp.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        "Remove sensitive fields from JWT payloads. Use encrypted JWTs (JWE) "
                                + "if sensitive data must be included.",
                        AuditIssueSeverity.HIGH,
                        reqResp
                ));
            }

        } catch (Exception e) {
            api.logging().logToError("[JWT Scanner] Error analyzing JWT: " + e.getMessage());
        }

        return issues;
    }

    /**
     * Decode a Base64URL-encoded string (no padding, URL-safe alphabet).
     */
    private byte[] base64UrlDecode(String input) {
        // Add padding if necessary
        String padded = input;
        switch (padded.length() % 4) {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Base64.getUrlDecoder().decode(padded);
    }
}
