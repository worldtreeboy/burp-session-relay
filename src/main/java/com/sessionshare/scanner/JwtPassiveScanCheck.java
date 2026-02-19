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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive scan check that analyzes JWTs found in HTTP traffic for security issues:
 * - Algorithm "none" (signature bypass)
 * - Weak algorithms (HS256 with potentially brute-forceable secret)
 * - Missing expiry (no "exp" claim)
 * - Expired tokens still accepted
 * - Sensitive data in payload (password, ssn, credit_card, etc.)
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
        // No active scanning — passive only
        return AuditResult.auditResult();
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
                if ("HS256".equalsIgnoreCase(alg)) {
                    issues.add(AuditIssue.auditIssue(
                            "JWT Uses HS256 Algorithm",
                            "A JWT using HS256 (HMAC-SHA256) was detected. HS256 is susceptible to "
                                    + "brute-force attacks if the signing secret is weak. Consider using "
                                    + "asymmetric algorithms (RS256, ES256) instead."
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
                // Check 4: Expired token still accepted
                long exp = payload.get("exp").getAsLong();
                if (Instant.ofEpochSecond(exp).isBefore(Instant.now())) {
                    issues.add(AuditIssue.auditIssue(
                            "Expired JWT Accepted",
                            "A JWT with an expired \"exp\" claim was found in traffic, suggesting "
                                    + "the server may accept expired tokens. Expiry: "
                                    + Instant.ofEpochSecond(exp)
                                    + "\n\nJWT Payload: " + payloadJson,
                            null,
                            reqResp.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            null,
                            "Ensure the server validates the \"exp\" claim and rejects expired tokens.",
                            AuditIssueSeverity.HIGH,
                            reqResp
                    ));
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
