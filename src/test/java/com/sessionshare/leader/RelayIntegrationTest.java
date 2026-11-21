package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.follower.SelectiveSocksProxy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Exercises ordinary SOCKS traffic against synthetic loopback services only. */
@Timeout(15)
class RelayIntegrationTest {
    private static final String PASSWORD = "loopback-test-password";
    static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    @Test void leaderRelaysHttpAndPropagatesDestinationEof() throws Exception {
        SocksRelayServer leader = leader("localhost");
        try (ToyHttp target = new ToyHttp(); Socket client = connect(port(leader))) {
            authenticate(client, PASSWORD);
            assertEquals(0, requestConnect(client, "localhost", target.port()));

            assertTrue(fetch(client).endsWith("loopback response"));
            assertTrue(target.request().startsWith("GET /toy HTTP/1.1"));
            assertEquals(1, leader.getTotalConnections());
        } finally {
            leader.stop();
        }
        await(() -> leader.getActiveConnections() == 0);
    }

    @Test void followerRoutesScopedHostnameThroughLeader() throws Exception {
        SocksRelayServer leader = leader("localhost");
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try (ToyHttp target = new ToyHttp()) {
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), PASSWORD, "localhost");
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(0, requestConnect(client, "localhost", target.port()));

                assertTrue(fetch(client).endsWith("loopback response"));
                assertTrue(target.request().contains("Host: localhost"));
                assertEquals(1, leader.getTotalConnections());
            }
        } finally {
            follower.stop();
            leader.stop();
        }
        await(() -> leader.getActiveConnections() == 0);
    }

    @Test void clientHalfCloseStillAllowsCompleteResponse() throws Exception {
        SocksRelayServer leader = leader("localhost");
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try (ToyHttp target = new ToyHttp()) {
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), PASSWORD, "localhost");
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(0, requestConnect(client, "localhost", target.port()));
                sendRequest(client);
                client.shutdownOutput();

                assertTrue(new String(client.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                        .endsWith("loopback response"));
                assertTrue(target.request().startsWith("GET /toy HTTP/1.1"));
            }
        } finally {
            follower.stop();
            leader.stop();
        }
    }

    @Test void followerConnectsUnscopedLoopbackHostDirectly() throws Exception {
        SocksRelayServer leader = leader("localhost");
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try (ToyHttp target = new ToyHttp()) {
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), PASSWORD, "unused.invalid");
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(0, requestConnect(client, "localhost", target.port()));
                assertTrue(fetch(client).endsWith("loopback response"));
                assertEquals(0, leader.getTotalConnections());
            }
        } finally {
            follower.stop();
            leader.stop();
        }
    }

    @Test void wrongLeaderPasswordClosesUpstreamSocketWithoutDirectFallback() throws Exception {
        SocksRelayServer leader = leader("localhost");
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try (ServerSocket target = new ServerSocket(0, 1, InetAddress.getByName("localhost"))) {
            target.setSoTimeout(250);
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), "incorrect", "localhost");
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertNotEquals(0, requestConnect(client, "localhost", target.getLocalPort()));
                assertEquals(-1, client.getInputStream().read());
            }
            await(() -> leader.getActiveConnections() == 0 && socketsEmpty(follower));
            assertThrows(java.net.SocketTimeoutException.class, target::accept);
        } finally {
            follower.stop();
            leader.stop();
        }
    }

    @Test void unlistedNumericDestinationsRequireExplicitDirectRouting() throws Exception {
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try (ServerSocket target = new ServerSocket(0, 1, LOOPBACK)) {
            follower.start(0, "127.0.0.1", 1, PASSWORD, "example.test");
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(2, requestConnect(client, InetAddress.getByName("127.0.0.1"), target.getLocalPort()));
            }
            target.setSoTimeout(200);
            assertThrows(java.net.SocketTimeoutException.class, target::accept);
            follower.stop();
            follower.start(0, "127.0.0.1", 1, PASSWORD, "example.test", true);
            try (Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(0, requestConnect(client, InetAddress.getByName("127.0.0.1"), target.getLocalPort()));
                try (Socket accepted = target.accept()) {
                    assertTrue(accepted.getInetAddress().isLoopbackAddress());
                }
            }
        } finally {
            follower.stop();
        }
    }

    @Test void bracketedIpv6ScopeRoutesBinaryAddressThroughLeader() throws Exception {
        InetAddress ipv6Loopback = InetAddress.getByName("::1");
        try (ServerSocket target = new ServerSocket()) {
            try {
                target.bind(new java.net.InetSocketAddress(ipv6Loopback, 0));
            } catch (java.net.SocketException unavailable) {
                org.junit.jupiter.api.Assumptions.abort("IPv6 loopback unavailable: " + unavailable);
            }
            SocksRelayServer leader = leader("[::1]");
            SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
            try {
                follower.start(0, "127.0.0.1", port(leader), PASSWORD, "[::1]");
                try (Socket client = connect(port(follower))) {
                    noAuthentication(client);
                    assertEquals(0, requestConnect(client, ipv6Loopback, target.getLocalPort()));
                    assertEquals(1, leader.getTotalConnections());
                }
            } finally {
                follower.stop();
                leader.stop();
            }
        }
    }

    @Test void leaderRequiresAuthenticationAndRestrictsScope() throws Exception {
        SocksRelayServer leader = leader("unused.invalid");
        try {
            try (Socket client = connect(port(leader))) {
                client.getOutputStream().write(new byte[]{5, 1, 0});
                assertArrayEquals(new byte[]{5, (byte) 255}, client.getInputStream().readNBytes(2));
            }
            try (ServerSocket target = new ServerSocket(0, 1, InetAddress.getByName("localhost"));
                 Socket client = connect(port(leader))) {
                authenticate(client, PASSWORD);
                assertNotEquals(0, requestConnect(client, "localhost", target.getLocalPort()));
            }
        } finally {
            leader.stop();
        }
    }

    @Test void stopClosesIdleHandshakesAndProxyCanRestart() throws Exception {
        SocksRelayServer leader = leader("localhost");
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try {
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), PASSWORD, "localhost");
            try (Socket first = connect(port(leader)); Socket second = connect(port(follower))) {
                first.getOutputStream().write(5);
                second.getOutputStream().write(5);
                await(() -> leader.getActiveConnections() == 1 && !socketsEmpty(follower));
                follower.stop();
                leader.stop();
                assertSocketClosed(first);
                assertSocketClosed(second);
            }
            await(() -> leader.getActiveConnections() == 0);
            leader.start(0, LOOPBACK);
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), PASSWORD, "localhost");
            try (ToyHttp target = new ToyHttp(); Socket client = connect(port(follower))) {
                noAuthentication(client);
                assertEquals(0, requestConnect(client, "localhost", target.port()));
                assertTrue(fetch(client).endsWith("loopback response"));
            }
        } finally {
            follower.stop();
            leader.stop();
        }
    }

    private static SocksRelayServer leader(String scope) throws IOException {
        SocksRelayServer leader = new SocksRelayServer(api());
        leader.setPassword(PASSWORD);
        leader.setAllowedScope(scope);
        leader.start(0, LOOPBACK);
        return leader;
    }

    private static void noAuthentication(Socket client) throws IOException {
        client.getOutputStream().write(new byte[]{5, 1, 0});
        assertArrayEquals(new byte[]{5, 0}, client.getInputStream().readNBytes(2));
    }

    private static void authenticate(Socket client, String password) throws IOException {
        OutputStream out = client.getOutputStream();
        InputStream in = client.getInputStream();
        out.write(new byte[]{5, 1, 2});
        assertArrayEquals(new byte[]{5, 2}, in.readNBytes(2));
        byte[] pass = password.getBytes(StandardCharsets.UTF_8);
        out.write(new byte[]{1, 1, 'u', (byte) pass.length});
        out.write(pass);
        assertArrayEquals(new byte[]{1, 0}, in.readNBytes(2));
    }

    private static int requestConnect(Socket client, String host, int port) throws IOException {
        byte[] name = host.getBytes(StandardCharsets.UTF_8);
        OutputStream out = client.getOutputStream();
        out.write(new byte[]{5, 1, 0, 3, (byte) name.length});
        out.write(name);
        return completeConnect(client, port);
    }

    private static int requestConnect(Socket client, InetAddress address, int port) throws IOException {
        byte[] bytes = address.getAddress();
        OutputStream out = client.getOutputStream();
        out.write(new byte[]{5, 1, 0, (byte) (bytes.length == 16 ? 4 : 1)});
        out.write(bytes);
        return completeConnect(client, port);
    }

    private static int completeConnect(Socket client, int port) throws IOException {
        OutputStream out = client.getOutputStream();
        out.write(port >>> 8);
        out.write(port & 255);
        byte[] reply = client.getInputStream().readNBytes(10);
        assertEquals(10, reply.length);
        assertEquals(5, reply[0]);
        return reply[1] & 255;
    }

    private static void sendRequest(Socket client) throws IOException {
        client.getOutputStream().write(("GET /toy HTTP/1.1\r\nHost: localhost\r\n"
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
    }

    private static String fetch(Socket client) throws IOException {
        sendRequest(client);
        return new String(client.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    static Socket connect(int port) throws IOException {
        Socket socket = new Socket();
        socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 3_000);
        socket.setSoTimeout(3_000);
        return socket;
    }

    static int port(Object server) throws ReflectiveOperationException {
        Field field = server.getClass().getDeclaredField("serverSocket");
        field.setAccessible(true);
        ServerSocket listener = (ServerSocket) field.get(server);
        assertTrue(listener.getInetAddress().isLoopbackAddress());
        return listener.getLocalPort();
    }

    private static boolean socketsEmpty(Object server) {
        try {
            Field field = server.getClass().getDeclaredField("openSockets");
            field.setAccessible(true);
            return ((Set<?>) field.get(server)).isEmpty();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean(), "Condition did not complete within four seconds");
    }

    private static void assertSocketClosed(Socket socket) throws IOException {
        try {
            assertEquals(-1, socket.getInputStream().read());
        } catch (java.net.SocketException expectedReset) {
            // Windows may report a reset when shutdown closes an incomplete handshake.
        }
    }

    static MontoyaApi api() {
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("logging")) {
                        return Proxy.newProxyInstance(method.getReturnType().getClassLoader(),
                                new Class<?>[]{method.getReturnType()}, (p, m, a) -> null);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static final class ToyHttp implements AutoCloseable {
        private final ServerSocket listener;
        private final ExecutorService worker;
        private final Future<String> request;
        private volatile Socket accepted;

        ToyHttp() throws IOException {
            listener = new ServerSocket(0, 1, InetAddress.getByName("localhost"));
            assertTrue(listener.getInetAddress().isLoopbackAddress());
            listener.setSoTimeout(5_000);
            worker = Executors.newSingleThreadExecutor(r -> {
                Thread thread = new Thread(r, "Loopback-http-test");
                thread.setDaemon(true);
                return thread;
            });
            request = worker.submit(() -> {
                try (Socket socket = listener.accept()) {
                    accepted = socket;
                    socket.setSoTimeout(3_000);
                    StringBuilder headers = new StringBuilder();
                    InputStream in = socket.getInputStream();
                    while (!headers.toString().endsWith("\r\n\r\n") && headers.length() < 8192) {
                        int next = in.read();
                        if (next < 0) throw new IOException("Incomplete toy request");
                        headers.append((char) next);
                    }
                    byte[] body = "loopback response".getBytes(StandardCharsets.UTF_8);
                    socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nConnection: close\r\n"
                            + "Content-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().write(body);
                    return headers.toString();
                }
            });
        }

        int port() { return listener.getLocalPort(); }
        String request() throws Exception { return request.get(4, TimeUnit.SECONDS); }

        @Override public void close() throws IOException {
            listener.close();
            Socket socket = accepted;
            if (socket != null) socket.close();
            worker.shutdownNow();
        }
    }
}
