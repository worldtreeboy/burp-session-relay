package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.model.TokenStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class TokenSharingIntegrationTest {
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    @Test void followerImportsAuthenticatedTokensFromLeader() throws Exception {
        TokenStore source = new TokenStore();
        source.setTarget("localhost");
        source.applyCapturedResponseForUrl("https://localhost/", java.util.List.of(), "synthetic-token", null, java.util.Map.of());
        TokenServer leader = new TokenServer(api(), source);
        TokenStore destination = new TokenStore();
        destination.setTarget("localhost");
        TokenPoller follower = new TokenPoller(api(), destination);
        try {
            leader.setPassword("loopback-password");
            leader.start(0, LOOPBACK);
            follower.setLeaderPort(port(leader));
            follower.setPassword("loopback-password");
            follower.setPollIntervalSeconds(3600);
            follower.start();

            await(() -> follower.getLastFetchTime() != null);

            assertEquals("synthetic-token", destination.getJwt());
            assertEquals("", follower.getLastError());
            assertEquals(0, follower.getConsecutiveFailures());
            assertEquals(1, leader.getRequestCount());
        } finally {
            follower.stop();
            leader.stop();
        }
    }

    @Test void emptyPasswordsCannotStartEitherTokenEndpoint() {
        TokenServer leader = new TokenServer(api(), new TokenStore());
        TokenPoller follower = new TokenPoller(api(), new TokenStore());

        assertThrows(IllegalArgumentException.class, () -> leader.start(0, LOOPBACK));
        assertThrows(IllegalArgumentException.class, follower::start);
        assertFalse(leader.isRunning());
        assertFalse(follower.isConnected());
    }

    @Test void tokenServerFailsClosedWhenPasswordIsClearedAndDisablesCaching() throws Exception {
        TokenServer leader = new TokenServer(api(), new TokenStore());
        try {
            leader.setPassword("loopback-password");
            leader.start(0, LOOPBACK);
            HttpURLConnection authorized = connection(port(leader), "loopback-password");
            try {
                assertEquals(200, authorized.getResponseCode());
                assertEquals("no-store", authorized.getHeaderField("Cache-Control"));
            } finally {
                authorized.disconnect();
            }
            leader.setPassword("");
            HttpURLConnection unauthenticated = connection(port(leader), null);
            try {
                assertEquals(401, unauthenticated.getResponseCode());
            } finally {
                unauthenticated.disconnect();
            }
        } finally {
            leader.stop();
        }
    }

    @Test void followerRefusesRedirectsAndClearsPreviouslySharedTokens() throws Exception {
        TokenStore store = new TokenStore();
        store.setTarget("localhost");
        store.applyCapturedResponseForUrl("https://localhost/", java.util.List.of(), "existing-synthetic-token", null, java.util.Map.of());
        TokenPoller follower = new TokenPoller(api(), store);
        ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "Loopback-token-redirect-test");
            thread.setDaemon(true);
            return thread;
        });
        try (ServerSocket origin = new ServerSocket(0, 1, LOOPBACK);
             ServerSocket redirectDestination = new ServerSocket(0, 1, LOOPBACK)) {
            origin.setSoTimeout(3_000);
            redirectDestination.setSoTimeout(250);
            Future<?> response = worker.submit(() -> {
                try (Socket client = origin.accept()) {
                    client.setSoTimeout(3_000);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            client.getInputStream(), StandardCharsets.US_ASCII));
                    String line;
                    int lines = 0;
                    while ((line = reader.readLine()) != null && !line.isEmpty()) {
                        if (++lines > 100) throw new IllegalStateException("Unexpected request size");
                    }
                    client.getOutputStream().write(("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:"
                            + redirectDestination.getLocalPort() + "/tokens\r\n"
                            + "Content-Length: 0\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            follower.setLeaderPort(origin.getLocalPort());
            follower.setPassword("loopback-password");
            follower.setPollIntervalSeconds(3600);
            follower.start();

            await(() -> follower.getConsecutiveFailures() == 1);
            response.get(4, TimeUnit.SECONDS);

            assertNull(follower.getLastFetchTime());
            assertTrue(follower.getLastError().contains("redirect"));
            assertEquals("", store.getJwt());
            assertThrows(SocketTimeoutException.class, redirectDestination::accept);
        } finally {
            follower.stop();
            worker.shutdownNow();
        }
    }

    private static int port(TokenServer server) throws ReflectiveOperationException {
        Field field = TokenServer.class.getDeclaredField("serverSocket");
        field.setAccessible(true);
        ServerSocket listener = (ServerSocket) field.get(server);
        assertTrue(listener.getInetAddress().isLoopbackAddress());
        return listener.getLocalPort();
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean(), "Condition did not complete within four seconds");
    }

    private static MontoyaApi api() {
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("logging")) {
                        return Proxy.newProxyInstance(method.getReturnType().getClassLoader(),
                                new Class<?>[]{method.getReturnType()}, (p, m, a) -> null);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static HttpURLConnection connection(int port, String password) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/tokens")
                .openConnection(java.net.Proxy.NO_PROXY);
        connection.setConnectTimeout(3_000);
        connection.setReadTimeout(3_000);
        if (password != null) connection.setRequestProperty("X-Auth", password);
        return connection;
    }
}
