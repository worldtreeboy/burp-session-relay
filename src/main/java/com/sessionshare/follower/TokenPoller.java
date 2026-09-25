package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.model.TokenStore;

import java.io.IOException;
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
    private boolean pollInProgress;
    private long generation;
    private HttpURLConnection activeConnection;
    private volatile int consecutiveFailures = 0;

    private String leaderIp = "127.0.0.1";
    private int leaderPort = 8888;
    private String password = "";
    private int pollIntervalSeconds = 5;

    public TokenPoller(MontoyaApi api, TokenStore tokenStore) {
        this.api = api;
        this.tokenStore = tokenStore;
    }

    // --- Configuration setters ---

    public synchronized void setLeaderIp(String ip) {
        this.leaderIp = ip;
    }

    public synchronized void setLeaderPort(int port) {
        this.leaderPort = port;
    }

    public synchronized void setPassword(String password) {
        this.password = password;
    }

    public synchronized void setPollIntervalSeconds(int seconds) {
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

    public int getConsecutiveFailures() { return consecutiveFailures; }

    /**
     * Start polling the leader's server on a background thread.
     */
    public synchronized void start() {
        if (connected) return;
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("A password is required");
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionShare-Poller");
            t.setDaemon(true);
            return t;
        });

        connected = true;
        long runGeneration = ++generation;
        lastFetchTime = null;
        lastError = "";
        consecutiveFailures = 0;
        scheduler.scheduleAtFixedRate(() -> poll(runGeneration), 0, pollIntervalSeconds, TimeUnit.SECONDS);
        api.logging().logToOutput("[Follower] Started polling " + leaderIp + ":" + leaderPort
                + " every " + pollIntervalSeconds + "s");
    }

    /**
     * Stop polling and shut down the scheduler.
     */
    public void stop() {
        HttpURLConnection connection;
        synchronized (this) {
            connected = false;
            generation++;
            pollInProgress = false;
            connection = activeConnection;
            activeConnection = null;
            if (scheduler != null) {
                scheduler.shutdownNow();
                scheduler = null;
            }
        }
        if (connection != null) connection.disconnect();
        api.logging().logToOutput("[Follower] Stopped polling.");
    }

    /**
     * Perform a single poll to fetch tokens from the leader.
     * Can also be called on-demand (e.g., on 401/403 response).
     */
    public void poll() {
        long runGeneration;
        synchronized (this) { runGeneration = generation; }
        poll(runGeneration);
    }

    private void poll(long runGeneration) {
        HttpURLConnection conn = null;
        try {
            synchronized (this) {
                if (!connected || generation != runGeneration || pollInProgress) return;
                URL url = new URL("http", leaderIp, leaderPort, "/tokens");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);
                conn.setRequestProperty("Cache-Control", "no-store");
                conn.setRequestProperty("X-Auth", password);
                activeConnection = conn;
                pollInProgress = true;
            }

            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                // Read the response body
                StringBuilder response = new StringBuilder();
                try (InputStreamReader reader = new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)) {
                    char[] buffer = new char[4096];
                    int count;
                    while ((count = reader.read(buffer)) != -1) {
                        if (response.length() + count > 1_048_576) {
                            throw new IOException("Token response exceeds the size limit");
                        }
                        response.append(buffer, 0, count);
                    }
                }

                synchronized (this) {
                    if (!connected || generation != runGeneration) return;
                    tokenStore.fromJson(response.toString());
                    lastFetchTime = Instant.now();
                    lastError = "";
                    consecutiveFailures = 0;
                }

                api.logging().logToOutput("[Follower] Fetched tokens successfully at " + lastFetchTime);
            } else if (responseCode == 401) {
                recordFailure(runGeneration, "Authentication failed (wrong password)");
            } else {
                recordFailure(runGeneration, responseCode >= 300 && responseCode < 400
                        ? "Leader redirected the request; redirects are not allowed" : "HTTP " + responseCode);
            }
        } catch (Exception e) {
            recordFailure(runGeneration, e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
            synchronized (this) {
                if (conn != null && activeConnection == conn) {
                    activeConnection = null;
                    pollInProgress = false;
                }
            }
        }
    }

    private synchronized void recordFailure(long runGeneration, String message) {
        if (!connected || generation != runGeneration) return;
        lastError = message == null ? "Unable to fetch tokens" : message;
        consecutiveFailures++;
        api.logging().logToError("[Follower] Poll failed: " + lastError);
    }
}
