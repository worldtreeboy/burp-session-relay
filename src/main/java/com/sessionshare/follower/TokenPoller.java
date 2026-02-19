package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.model.TokenStore;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Follower-side background thread that periodically polls the leader's
 * embedded HTTP server to fetch the latest session tokens.
 */
public class TokenPoller {

    private final MontoyaApi api;
    private final TokenStore tokenStore;

    private ScheduledExecutorService scheduler;
    private volatile boolean connected = false;
    private volatile Instant lastFetchTime;
    private volatile String lastError = "";

    private String leaderIp = "127.0.0.1";
    private int leaderPort = 8888;
    private String password = "";
    private int pollIntervalSeconds = 5;

    public TokenPoller(MontoyaApi api, TokenStore tokenStore) {
        this.api = api;
        this.tokenStore = tokenStore;
    }

    // --- Configuration setters ---

    public void setLeaderIp(String ip) {
        this.leaderIp = ip;
    }

    public void setLeaderPort(int port) {
        this.leaderPort = port;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setPollIntervalSeconds(int seconds) {
        this.pollIntervalSeconds = Math.max(1, seconds);
    }

    // --- Status getters ---

    public boolean isConnected() {
        return connected;
    }

    public Instant getLastFetchTime() {
        return lastFetchTime;
    }

    public String getLastError() {
        return lastError;
    }

    /**
     * Start polling the leader's server on a background thread.
     */
    public void start() {
        if (connected) return;

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionShare-Poller");
            t.setDaemon(true);
            return t;
        });

        scheduler.scheduleAtFixedRate(this::poll, 0, pollIntervalSeconds, TimeUnit.SECONDS);
        connected = true;
        lastError = "";
        api.logging().logToOutput("[Follower] Started polling " + leaderIp + ":" + leaderPort
                + " every " + pollIntervalSeconds + "s");
    }

    /**
     * Stop polling and shut down the scheduler.
     */
    public void stop() {
        connected = false;
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        api.logging().logToOutput("[Follower] Stopped polling.");
    }

    /**
     * Perform a single poll to fetch tokens from the leader.
     * Can also be called on-demand (e.g., on 401/403 response).
     */
    public void poll() {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://" + leaderIp + ":" + leaderPort + "/tokens");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            // Send authentication header
            if (password != null && !password.isEmpty()) {
                conn.setRequestProperty("X-Auth", password);
            }

            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                // Read the response body
                StringBuilder response = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                }

                // Update our local token store
                tokenStore.fromJson(response.toString());
                lastFetchTime = Instant.now();
                lastError = "";

                api.logging().logToOutput("[Follower] Fetched tokens successfully at " + lastFetchTime);
            } else if (responseCode == 401) {
                lastError = "Authentication failed (wrong password)";
                api.logging().logToError("[Follower] 401 Unauthorized — check password");
            } else {
                lastError = "HTTP " + responseCode;
                api.logging().logToError("[Follower] Unexpected response: " + responseCode);
            }
        } catch (Exception e) {
            lastError = e.getMessage();
            api.logging().logToError("[Follower] Poll failed: " + e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
}
