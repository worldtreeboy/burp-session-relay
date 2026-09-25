package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.model.TokenStore;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Embedded HTTP server that runs inside the leader's Burp instance.
 * Serves the latest tokens to followers over the LAN.
 *
 * Uses raw java.net.ServerSocket instead of com.sun.net.httpserver
 * because Burp Suite's classloader does not expose the jdk.httpserver module.
 */
public class TokenServer {

    private final MontoyaApi api;
    private final TokenStore tokenStore;

    private ServerSocket serverSocket;
    private ExecutorService executor;
    private volatile boolean running = false;
    private volatile String password = "";
    private final Set<Socket> openSockets = ConcurrentHashMap.newKeySet();
    private final AtomicLong requestCount = new AtomicLong(0);

    public TokenServer(MontoyaApi api, TokenStore tokenStore) {
        this.api = api;
        this.tokenStore = tokenStore;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isRunning() {
        return running;
    }

    public long getRequestCount() {
        return requestCount.get();
    }

    /**
     * Start the embedded HTTP server on the given port.
     * Binds to 0.0.0.0 so followers on the LAN can connect.
     */
    public synchronized void start(int port) throws IOException {
        start(port, null);
    }

    // Allows loopback-only integration checks without exposing a test listener to the LAN.
    synchronized void start(int port, InetAddress bindAddress) throws IOException {
        if (running) {
            api.logging().logToOutput("[Server] Already running.");
            return;
        }

        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("A password is required");
        }
        serverSocket = new ServerSocket(port, 50, bindAddress);
        ServerSocket listener = serverSocket;
        executor = new ThreadPoolExecutor(5, 5, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(32), runnable -> {
                    Thread thread = new Thread(runnable, "SessionShare-TokenServer");
                    thread.setDaemon(true);
                    return thread;
                });
        ExecutorService workers = executor;
        running = true;

        // Accept loop runs on its own thread
        executor.submit(() -> {
            api.logging().logToOutput("[Server] Accept loop started on port " + port);
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    synchronized (this) {
                        if (!running || serverSocket != listener) {
                            close(client);
                            continue;
                        }
                        openSockets.add(client);
                        try {
                            workers.execute(() -> handleClient(client));
                        } catch (RejectedExecutionException e) {
                            openSockets.remove(client);
                            close(client);
                        }
                    }
                } catch (SocketException e) {
                    // Expected when serverSocket.close() is called during shutdown
                    if (running) {
                        api.logging().logToError("[Server] Accept error: " + e.getMessage());
                    }
                } catch (IOException e) {
                    if (running) {
                        api.logging().logToError("[Server] Accept error: " + e.getMessage());
                    }
                }
            }
            api.logging().logToOutput("[Server] Accept loop ended.");
        });

        api.logging().logToOutput("[Server] Started on port " + port);
    }

    /**
     * Stop the embedded server and release resources.
     */
    public synchronized void stop() {
        if (!running) return;
        running = false;

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            api.logging().logToError("[Server] Error closing socket: " + e.getMessage());
        }

        if (executor != null) {
            executor.shutdownNow();
        }
        for (Socket client : openSockets) close(client);
        openSockets.clear();

        api.logging().logToOutput("[Server] Stopped.");
    }

    // ==================== Client handling ====================

    private void handleClient(Socket client) {
        try (client;
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
             OutputStream out = client.getOutputStream()) {

            client.setSoTimeout(5000);

            // Read the HTTP request line: "GET /path HTTP/1.1"
            String requestLine = readLine(reader, 8192);
            if (requestLine == null || requestLine.isEmpty()) return;

            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                sendResponse(out, 400, "{\"error\": \"Bad request\"}");
                return;
            }

            String method = parts[0].toUpperCase(Locale.ROOT);
            String path = parts[1];

            // Read all headers
            String authValue = null;
            String line;
            int headerCharacters = 0;
            while ((line = readLine(reader, 8192)) != null && !line.isEmpty()) {
                headerCharacters += line.length() + 2;
                if (headerCharacters > 32768) throw new IOException("Request headers exceed the size limit");
                if (line.toLowerCase(Locale.ROOT).startsWith("x-auth:")) {
                    if (authValue != null) {
                        sendResponse(out, 400, "{\"error\": \"Duplicate authentication header\"}");
                        return;
                    }
                    authValue = line.substring("x-auth:".length()).trim();
                }
            }
            if (line == null) {
                sendResponse(out, 400, "{\"error\": \"Incomplete request\"}");
                return;
            }

            // Route the request
            if (!method.equals("GET")) {
                sendResponse(out, 405, "{\"error\": \"Method not allowed\"}");
                return;
            }

            if (path.equals("/tokens")) {
                handleTokens(out, authValue, client);
            } else if (path.equals("/health")) {
                handleHealth(out);
            } else {
                sendResponse(out, 404, "{\"error\": \"Not found\"}");
            }

        } catch (Exception e) {
            if (!client.isClosed()) api.logging().logToError("[Server] Client handler error: " + e.getMessage());
        } finally {
            openSockets.remove(client);
        }
    }

    private void handleTokens(OutputStream out, String authValue, Socket client) throws IOException {
        // Authenticate
        if (!authenticate(authValue)) {
            sendResponse(out, 401, "{\"error\": \"Unauthorized\"}");
            api.logging().logToOutput("[Server] Rejected unauthorized request from "
                    + client.getRemoteSocketAddress());
            return;
        }

        requestCount.incrementAndGet();
        String json = tokenStore.toJson();
        sendResponse(out, 200, json);
    }

    private void handleHealth(OutputStream out) throws IOException {
        String json = "{\"status\": \"ok\", \"requests\": " + requestCount.get() + "}";
        sendResponse(out, 200, json);
    }

    // ==================== Helpers ====================

    private boolean authenticate(String authValue) {
        String expected = password;
        return expected != null && !expected.isBlank() && authValue != null
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                authValue.getBytes(StandardCharsets.UTF_8));
    }

    private static String readLine(BufferedReader reader, int limit) throws IOException {
        StringBuilder line = new StringBuilder();
        int value;
        while ((value = reader.read()) != -1) {
            if (value == '\n') return line.toString();
            if (line.length() >= limit) throw new IOException("Request line exceeds the size limit");
            if (value != '\r') line.append((char) value);
        }
        return line.isEmpty() ? null : line.toString();
    }

    private static void close(Socket socket) {
        try { socket.close(); } catch (IOException ignored) { }
    }

    private void sendResponse(OutputStream out, int statusCode, String body) throws IOException {
        String statusText;
        switch (statusCode) {
            case 200: statusText = "OK"; break;
            case 400: statusText = "Bad Request"; break;
            case 401: statusText = "Unauthorized"; break;
            case 404: statusText = "Not Found"; break;
            case 405: statusText = "Method Not Allowed"; break;
            default:  statusText = "Error"; break;
        }

        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String response = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Cache-Control: no-store\r\n"
                + "Connection: close\r\n"
                + "\r\n";

        out.write(response.getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }
}
