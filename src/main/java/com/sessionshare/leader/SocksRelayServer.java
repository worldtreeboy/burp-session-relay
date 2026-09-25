package com.sessionshare.leader;

import burp.api.montoya.MontoyaApi;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import com.sessionshare.util.ScopeMatcher;

/**
 * Minimal SOCKS5 relay server (RFC 1928 CONNECT command + RFC 1929 username/password auth).
 *
 * Lets a follower point their own Burp's upstream SOCKS proxy (Project options -> Connections)
 * at the leader, so that follower's Burp traffic egresses through the leader's machine —
 * including through whatever VPN tunnel the leader has routed traffic into.
 *
 * CONNECT only: no BIND, no UDP ASSOCIATE. Domain names are resolved on the leader's side
 * (remote DNS), which is required for split-DNS VPNs to work.
 *
 * Uses raw java.net sockets for the same reason TokenServer does: Burp's classloader
 * doesn't expose extra JDK modules extensions might otherwise reach for.
 */
public class SocksRelayServer {

    private static final byte SOCKS_VERSION = 0x05;
    private static final byte AUTH_USER_PASS = 0x02;
    private static final byte AUTH_NO_ACCEPTABLE = (byte) 0xFF;
    private static final byte CMD_CONNECT = 0x01;
    private static final byte ATYP_IPV4 = 0x01;
    private static final byte ATYP_DOMAIN = 0x03;
    private static final byte ATYP_IPV6 = 0x04;

    private static final byte REPLY_SUCCEEDED = 0x00;
    private static final byte REPLY_HOST_UNREACHABLE = 0x04;
    private static final byte REPLY_CMD_NOT_SUPPORTED = 0x07;
    private static final byte REPLY_ATYP_NOT_SUPPORTED = 0x08;

    private final MontoyaApi api;

    private ServerSocket serverSocket;
    private ExecutorService executor;
    private volatile boolean running = false;
    private volatile String password = "";
    private volatile String allowedScope = "";
    private final Set<Socket> openSockets = ConcurrentHashMap.newKeySet();
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicLong totalConnections = new AtomicLong(0);

    public SocksRelayServer(MontoyaApi api) {
        this.api = api;
    }

    public void setPassword(String password) {
        this.password = password == null ? "" : password;
    }

    public void setAllowedScope(String allowedScope) {
        this.allowedScope = allowedScope == null ? "" : allowedScope;
    }

    public boolean isRunning() {
        return running;
    }

    public int getActiveConnections() {
        return activeConnections.get();
    }

    public long getTotalConnections() {
        return totalConnections.get();
    }

    /**
     * Start the SOCKS5 relay on the given port. Binds to 0.0.0.0 so followers on the LAN can connect.
     */
    public synchronized void start(int port) throws IOException {
        start(port, null);
    }

    // Allows loopback-only integration checks without exposing a test listener to the LAN.
    synchronized void start(int port, InetAddress bindAddress) throws IOException {
        if (running) {
            api.logging().logToOutput("[SOCKS] Already running.");
            return;
        }

        if (password.isBlank()) throw new IllegalArgumentException("A password is required for SOCKS relay");
        if (password.getBytes(StandardCharsets.UTF_8).length > 255) {
            throw new IllegalArgumentException("SOCKS password must be at most 255 UTF-8 bytes");
        }
        if (allowedScope.isBlank()) throw new IllegalArgumentException("Target scope is required for SOCKS relay");
        serverSocket = new ServerSocket(port, 50, bindAddress);
        ServerSocket listener = serverSocket;
        executor = new ThreadPoolExecutor(32, 32, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(64), runnable -> {
                    Thread thread = new Thread(runnable, "SessionShare-SocksRelay");
                    thread.setDaemon(true);
                    return thread;
                });
        ExecutorService workers = executor;
        running = true;

        executor.submit(() -> {
            api.logging().logToOutput("[SOCKS] Accept loop started on port " + port);
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    synchronized (this) {
                        if (!track(client, listener)) continue;
                        try {
                            workers.execute(() -> handleClient(client, listener));
                        } catch (RejectedExecutionException e) {
                            openSockets.remove(client);
                            closeQuietly(client);
                        }
                    }
                } catch (SocketException e) {
                    // Expected when serverSocket.close() is called during shutdown
                    if (running) {
                        api.logging().logToError("[SOCKS] Accept error: " + e.getMessage());
                    }
                } catch (IOException e) {
                    if (running) {
                        api.logging().logToError("[SOCKS] Accept error: " + e.getMessage());
                    }
                }
            }
            api.logging().logToOutput("[SOCKS] Accept loop ended.");
        });

        api.logging().logToOutput("[SOCKS] Started on port " + port);
    }

    /**
     * Stop the relay and release resources. Active relayed connections are force-closed.
     */
    public synchronized void stop() {
        if (!running) return;
        running = false;

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            api.logging().logToError("[SOCKS] Error closing socket: " + e.getMessage());
        }

        if (executor != null) {
            executor.shutdownNow();
        }
        for (Socket socket : openSockets) closeQuietly(socket);
        openSockets.clear();

        api.logging().logToOutput("[SOCKS] Stopped.");
    }

    // ==================== Per-connection handling ====================

    private void handleClient(Socket client, ServerSocket listener) {
        Socket target = null;
        totalConnections.incrementAndGet();
        activeConnections.incrementAndGet();
        try {
            client.setSoTimeout(10_000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            if (!doHandshake(in, out, client)) {
                return;
            }

            String[] dest = readConnectRequest(in, out);
            if (dest == null) {
                return;
            }

            String host = dest[0];
            int port = Integer.parseInt(dest[1]);

            if (!ScopeMatcher.matchesHost(host, allowedScope)) {
                api.logging().logToError("[SOCKS] Blocked out-of-scope destination " + host + ":" + port);
                sendConnectReply(out, REPLY_HOST_UNREACHABLE);
                return;
            }

            try {
                target = new Socket();
                if (!track(target, listener)) return;
                target.connect(new InetSocketAddress(host, port), 10_000);
            } catch (Exception e) {
                api.logging().logToError("[SOCKS] Connect failed to " + host + ":" + port + " — " + e.getMessage());
                sendConnectReply(out, REPLY_HOST_UNREACHABLE);
                return;
            }

            sendConnectReply(out, REPLY_SUCCEEDED);
            api.logging().logToOutput("[SOCKS] Relaying " + client.getRemoteSocketAddress()
                    + " -> " + host + ":" + port);

            // Handshake is done — from here it's a raw byte pump in both directions.
            client.setSoTimeout(0);
            target.setSoTimeout(0);
            pump(client, target);

        } catch (Exception e) {
            api.logging().logToError("[SOCKS] Client handler error: " + e.getMessage());
        } finally {
            activeConnections.decrementAndGet();
            closeQuietly(client);
            closeQuietly(target);
            openSockets.remove(client);
            if (target != null) openSockets.remove(target);
        }
    }

    /**
     * Greeting + method negotiation. Returns true once the client is authenticated
     * and ready for the CONNECT request.
     */
    private boolean doHandshake(InputStream in, OutputStream out, Socket client) throws IOException {
        int ver = readByte(in);
        if (ver != SOCKS_VERSION) {
            api.logging().logToError("[SOCKS] Unsupported version byte: " + ver);
            return false;
        }

        int nMethods = readByte(in);
        byte[] methods = readFully(in, nMethods);

        boolean offersUserPass = false;
        for (byte m : methods) {
            if (m == AUTH_USER_PASS) offersUserPass = true;
        }

        if (password.isBlank() || !offersUserPass) {
            out.write(new byte[]{SOCKS_VERSION, AUTH_NO_ACCEPTABLE});
            out.flush();
            return false;
        }
        out.write(new byte[]{SOCKS_VERSION, AUTH_USER_PASS});
        out.flush();
        return doUserPassAuth(in, out, client);
    }

    /**
     * RFC 1929 username/password sub-negotiation. The username is accepted as-is
     * (Burp's SOCKS proxy UI requires one); only the password is checked against
     * the leader's shared secret.
     */
    private boolean doUserPassAuth(InputStream in, OutputStream out, Socket client) throws IOException {
        int subVer = readByte(in);
        if (subVer != 0x01) {
            out.write(new byte[]{0x01, 0x01});
            out.flush();
            return false;
        }

        int ulen = readByte(in);
        readFully(in, ulen); // username — unused, just drained off the wire
        int plen = readByte(in);
        byte[] passwd = readFully(in, plen);

        String expected = password;
        boolean ok = ulen > 0 && plen > 0 && !expected.isBlank()
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), passwd);

        out.write(new byte[]{0x01, (byte) (ok ? 0x00 : 0x01)});
        out.flush();

        if (!ok) {
            api.logging().logToOutput("[SOCKS] Rejected bad credentials from " + client.getRemoteSocketAddress());
        }
        return ok;
    }

    /**
     * Reads the CONNECT request. Returns {host, port}, or null (after sending an error reply) on failure.
     */
    private String[] readConnectRequest(InputStream in, OutputStream out) throws IOException {
        int ver = readByte(in);
        int cmd = readByte(in);
        int reserved = readByte(in);
        int atyp = readByte(in);

        if (ver != SOCKS_VERSION || reserved != 0) return null;

        if (cmd != CMD_CONNECT) {
            sendConnectReply(out, REPLY_CMD_NOT_SUPPORTED);
            return null;
        }

        String host;
        switch (atyp) {
            case ATYP_IPV4: {
                byte[] addr = readFully(in, 4);
                host = InetAddress.getByAddress(addr).getHostAddress();
                break;
            }
            case ATYP_DOMAIN: {
                int len = readByte(in);
                byte[] nameBytes = readFully(in, len);
                host = new String(nameBytes, StandardCharsets.UTF_8);
                break;
            }
            case ATYP_IPV6: {
                byte[] addr = readFully(in, 16);
                host = InetAddress.getByAddress(addr).getHostAddress();
                break;
            }
            default:
                sendConnectReply(out, REPLY_ATYP_NOT_SUPPORTED);
                return null;
        }

        int port = (readByte(in) << 8) | readByte(in);
        if (host.isBlank() || port == 0) {
            sendConnectReply(out, REPLY_HOST_UNREACHABLE);
            return null;
        }
        return new String[]{host, String.valueOf(port)};
    }

    private void sendConnectReply(OutputStream out, byte replyCode) throws IOException {
        // BND.ADDR/BND.PORT are purely informational for CONNECT — 0.0.0.0:0 is fine.
        out.write(new byte[]{SOCKS_VERSION, replyCode, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0});
        out.flush();
    }

    // ==================== Byte pump ====================

    private void pump(Socket a, Socket b) {
        Thread t1 = new Thread(() -> copy(a, b), "SOCKS-pump");
        Thread t2 = new Thread(() -> copy(b, a), "SOCKS-pump");
        t1.setDaemon(true);
        t2.setDaemon(true);
        t1.start();
        t2.start();

        try {
            t1.join();
            t2.join();
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(a);
            closeQuietly(b);
        }
    }

    private void copy(Socket from, Socket to) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
            // Preserve a half-close so an HTTP response can finish after its request ends.
            to.shutdownOutput();
        } catch (IOException ignored) {
            closeQuietly(from);
            closeQuietly(to);
        }
    }

    // ==================== Helpers ====================

    private synchronized boolean track(Socket socket, ServerSocket listener) {
        if (!running || serverSocket != listener) {
            closeQuietly(socket);
            return false;
        }
        openSockets.add(socket);
        return true;
    }

    private int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b == -1) throw new EOFException("Unexpected end of stream");
        return b;
    }

    private byte[] readFully(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(buf, off, len - off);
            if (n == -1) throw new EOFException("Unexpected end of stream");
            off += n;
        }
        return buf;
    }

    private void closeQuietly(Socket s) {
        if (s != null && !s.isClosed()) {
            try {
                s.close();
            } catch (IOException ignored) {
                // Best-effort cleanup.
            }
        }
    }
}
