package com.sessionshare.session;

import burp.api.montoya.http.message.HttpHeader;
import com.sessionshare.model.TokenStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Values collected from one response, including the complete Set-Cookie fields. */
public record CapturedTokens(List<String> cookies, String jwt, String csrf, Map<String, String> customHeaders) {
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    private static final String CSRF_NAME = "name=[\"'](?:csrf[_-]?token|_csrf|xsrf[_-]?token)[\"']";
    private static final String CONTENT = "content=[\"']([^\"']+)[\"']";
    private static final List<Pattern> CSRF_META = List.of(
            Pattern.compile("<meta[^>]+" + CSRF_NAME + "[^>]+" + CONTENT, Pattern.CASE_INSENSITIVE),
            Pattern.compile("<meta[^>]+" + CONTENT + "[^>]+" + CSRF_NAME, Pattern.CASE_INSENSITIVE));

    public static CapturedTokens read(TokenStore store, List<HttpHeader> headers, String body, boolean loginResponse) {
        List<String> cookies = new ArrayList<>();
        Map<String, String> custom = new LinkedHashMap<>();
        String csrfHeader = store.getCsrfHeaderName();
        String jwt = null;
        String csrf = null;
        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                cookies.add(value);
                continue;
            }
            if ("Cookie".equalsIgnoreCase(name)) continue;
            Matcher bearer = JWT.matcher(value);
            if (bearer.find()) jwt = bearer.group();
            if (name.equalsIgnoreCase(csrfHeader)) csrf = value.trim();
            if (store.isWatchedHeader(name)) custom.put(name, value.trim());
        }
        if (body != null) {
            if (loginResponse) {
                Matcher bearer = JWT.matcher(body);
                if (bearer.find()) jwt = bearer.group();
            }
            if (!csrfHeader.isEmpty()) {
                for (Pattern pattern : CSRF_META) {
                    Matcher meta = pattern.matcher(body);
                    if (meta.find()) {
                        csrf = meta.group(1);
                        break;
                    }
                }
            }
        }
        return new CapturedTokens(cookies, jwt, csrf, custom);
    }
}
