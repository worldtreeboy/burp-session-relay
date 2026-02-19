package com.sessionshare;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.scanner.JwtPassiveScanCheck;
import com.sessionshare.session.SessionHttpHandler;
import com.sessionshare.session.SessionManager;
import com.sessionshare.ui.ConfigPanel;

/**
 * Session Share — Burp Suite extension for sharing session tokens across
 * a penetration testing team on the same LAN.
 *
 * Architecture: Leader/Follower model + standalone Session Manager.
 *   - Leader captures tokens from proxied traffic and serves them via an embedded HTTP server.
 *   - Followers poll the leader and auto-inject tokens into their outgoing requests.
 *   - Session Manager (independent): auto-refreshes expired tokens via a login macro,
 *     pre-checks JWT expiry, and retries on 401/403.
 *
 * Built on the Montoya API. No legacy burp.I* interfaces.
 */
public class SessionShareExtension implements BurpExtension {

    private TokenStore tokenStore;
    private TokenServer tokenServer;
    private TokenCaptureHandler captureHandler;
    private TokenPoller tokenPoller;
    private TokenInjector tokenInjector;
    private SessionManager sessionManager;
    private SessionHttpHandler sessionHttpHandler;
    private ConfigPanel configPanel;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Session Share");
        api.logging().logToOutput("Session Share v1.1 loading...");

        // 1. Core model — thread-safe token storage
        tokenStore = new TokenStore();

        // 2. Leader components
        tokenServer = new TokenServer(api, tokenStore);
        captureHandler = new TokenCaptureHandler(api, tokenStore);

        // 3. Follower components
        tokenPoller = new TokenPoller(api, tokenStore);
        tokenInjector = new TokenInjector(api, tokenStore, tokenPoller);

        // 4. Session Manager (works independently of leader/follower)
        sessionManager = new SessionManager(api, tokenStore);
        sessionHttpHandler = new SessionHttpHandler(api, tokenStore, sessionManager);

        // 5. Register HTTP handlers — all three check their own active/enabled flags
        api.http().registerHttpHandler(captureHandler);
        api.http().registerHttpHandler(tokenInjector);
        api.http().registerHttpHandler(sessionHttpHandler);

        // 6. Register proxy response handler — leader only captures from proxy traffic
        api.proxy().registerResponseHandler(captureHandler);

        // 7. Register passive + active JWT scanner
        api.scanner().registerScanCheck(new JwtPassiveScanCheck(api));

        // 8. Build and register the UI tab
        configPanel = new ConfigPanel(api, tokenStore, tokenServer, captureHandler,
                tokenPoller, tokenInjector, sessionManager);
        api.userInterface().registerSuiteTab("Session Share", configPanel);

        // 9. Cleanup on extension unload
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Session Share unloading...");

            // Stop leader server
            tokenServer.stop();
            captureHandler.setActive(false);

            // Stop follower polling
            tokenPoller.stop();
            tokenInjector.setActive(false);

            // Disable session manager
            sessionManager.setEnabled(false);

            // Stop UI refresh
            configPanel.stopUiRefresh();

            api.logging().logToOutput("Session Share unloaded.");
        });

        api.logging().logToOutput("Session Share v1.1 loaded successfully.");
        api.logging().logToOutput("Select Leader or Follower mode, and/or enable Session Manager in the Session Share tab.");
    }
}
