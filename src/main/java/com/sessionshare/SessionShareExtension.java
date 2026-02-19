package com.sessionshare;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.scanner.JwtPassiveScanCheck;
import com.sessionshare.ui.ConfigPanel;

/**
 * Session Share — Burp Suite extension for sharing session tokens across
 * a penetration testing team on the same LAN.
 *
 * Architecture: Leader/Follower model.
 *   - Leader captures tokens from proxied traffic and serves them via an embedded HTTP server.
 *   - Followers poll the leader and auto-inject tokens into their outgoing requests.
 *
 * Built on the Montoya API. No legacy burp.I* interfaces.
 */
public class SessionShareExtension implements BurpExtension {

    private TokenStore tokenStore;
    private TokenServer tokenServer;
    private TokenCaptureHandler captureHandler;
    private TokenPoller tokenPoller;
    private TokenInjector tokenInjector;
    private ConfigPanel configPanel;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Session Share");
        api.logging().logToOutput("Session Share v1.0 loading...");

        // 1. Core model — thread-safe token storage
        tokenStore = new TokenStore();

        // 2. Leader components
        tokenServer = new TokenServer(api, tokenStore);
        captureHandler = new TokenCaptureHandler(api, tokenStore);

        // 3. Follower components
        tokenPoller = new TokenPoller(api, tokenStore);
        tokenInjector = new TokenInjector(api, tokenStore, tokenPoller);

        // 4. Register HTTP handler — used by both leader (capture + inject) and follower (inject)
        //    The captureHandler handles leader-side capture + injection.
        //    The tokenInjector handles follower-side injection.
        //    Both check their own `active` flag, so only the relevant one operates.
        api.http().registerHttpHandler(captureHandler);
        api.http().registerHttpHandler(tokenInjector);

        // 5. Register proxy response handler — leader only captures from proxy traffic
        api.proxy().registerResponseHandler(captureHandler);

        // 6. Register passive JWT scanner
        api.scanner().registerScanCheck(new JwtPassiveScanCheck(api));

        // 7. Build and register the UI tab
        configPanel = new ConfigPanel(api, tokenStore, tokenServer, captureHandler,
                tokenPoller, tokenInjector);
        api.userInterface().registerSuiteTab("Session Share", configPanel);

        // 8. Cleanup on extension unload
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Session Share unloading...");

            // Stop leader server
            tokenServer.stop();
            captureHandler.setActive(false);

            // Stop follower polling
            tokenPoller.stop();
            tokenInjector.setActive(false);

            // Stop UI refresh
            configPanel.stopUiRefresh();

            api.logging().logToOutput("Session Share unloaded.");
        });

        api.logging().logToOutput("Session Share v1.0 loaded successfully.");
        api.logging().logToOutput("Select Leader or Follower mode in the Session Share tab.");
    }
}
