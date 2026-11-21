package com.sessionshare;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.follower.SelectiveSocksProxy;
import com.sessionshare.leader.SocksRelayServer;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.leader.TokenServer;
import com.sessionshare.model.TokenStore;
import com.sessionshare.session.SessionHttpHandler;
import com.sessionshare.session.SessionManager;
import com.sessionshare.ui.ConfigPanel;

import javax.swing.SwingUtilities;

/**
 * Burp Session Relay — Burp Suite extension for sharing session tokens and routes across
 * a penetration testing team on the same LAN.
 *
 * Architecture: Leader/Follower model + standalone Session Manager.
 *   - Leader captures tokens from proxied traffic and serves them via an embedded HTTP server.
 *   - Followers poll the leader and auto-inject tokens into their outgoing requests.
 *   - Session Manager (independent): auto-refreshes expired tokens via a login macro,
 *     pre-checks JWT expiry, and refreshes subsequent requests after 401/403.
 *
 * Built on the Montoya API. No legacy burp.I* interfaces.
 */
public class SessionShareExtension implements BurpExtension {

    private static final String VERSION = "1.2";

    private TokenStore tokenStore;
    private TokenServer tokenServer;
    private SocksRelayServer socksRelayServer;
    private TokenCaptureHandler captureHandler;
    private TokenPoller tokenPoller;
    private TokenInjector tokenInjector;
    private SelectiveSocksProxy selectiveSocksProxy;
    private SessionManager sessionManager;
    private SessionHttpHandler sessionHttpHandler;
    private ConfigPanel configPanel;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Burp Session Relay");
        api.logging().logToOutput("Burp Session Relay v" + VERSION + " loading...");

        // 1. Core model — thread-safe token storage
        tokenStore = new TokenStore();

        // 2. Leader components
        tokenServer = new TokenServer(api, tokenStore);
        socksRelayServer = new SocksRelayServer(api);
        captureHandler = new TokenCaptureHandler(api, tokenStore);

        // 3. Follower components
        tokenPoller = new TokenPoller(api, tokenStore);
        tokenInjector = new TokenInjector(api, tokenStore, tokenPoller);
        selectiveSocksProxy = new SelectiveSocksProxy(api);

        // 4. Session Manager (works independently of leader/follower)
        sessionManager = new SessionManager(api, tokenStore);
        sessionHttpHandler = new SessionHttpHandler(api, tokenStore, sessionManager);

        // 5. Register HTTP handlers — all three check their own active/enabled flags
        api.http().registerHttpHandler(captureHandler);
        api.http().registerHttpHandler(tokenInjector);
        api.http().registerHttpHandler(sessionHttpHandler);

        // 6. Register proxy response handler — leader only captures from proxy traffic
        api.proxy().registerResponseHandler(captureHandler);

        // 7. Build and register the UI tab
        Runnable createUi = () -> configPanel = new ConfigPanel(api, tokenStore, tokenServer,
                socksRelayServer, captureHandler, tokenPoller, tokenInjector,
                selectiveSocksProxy, sessionManager);
        if (SwingUtilities.isEventDispatchThread()) {
            createUi.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(createUi);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while creating extension UI", ex);
            } catch (java.lang.reflect.InvocationTargetException ex) {
                throw new IllegalStateException("Could not create extension UI", ex.getCause());
            }
        }
        api.userInterface().registerSuiteTab("Burp Session Relay", configPanel);

        // 8. Cleanup on extension unload
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Burp Session Relay unloading...");

            // Mark the UI disposed before a background login test can restore its state.
            configPanel.stopUiRefresh();

            // Stop leader server
            tokenServer.stop();
            socksRelayServer.stop();
            captureHandler.setActive(false);

            // Stop follower polling
            tokenPoller.stop();
            tokenInjector.setActive(false);
            selectiveSocksProxy.stop();

            // Disable session manager
            sessionManager.setEnabled(false);

            api.logging().logToOutput("Burp Session Relay unloaded.");
        });

        api.logging().logToOutput("Burp Session Relay v" + VERSION + " loaded successfully.");
        api.logging().logToOutput("Select Leader or Follower mode, and/or enable Session Manager in the Burp Session Relay tab.");
    }
}
