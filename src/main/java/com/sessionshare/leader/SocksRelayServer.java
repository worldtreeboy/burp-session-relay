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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

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
    private static final byte AUTH_NONE = 0x00;
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
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicLong totalConnections = new AtomicLong(0);

    public SocksRelayServer(MontoyaApi api) {
        this.api = api;
    }

    public void setPassword(String password) {
        this.password = password == null ? "" : password;
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
    public void start(int port) throws IOException {
        if (running) {
            api.logging().logToOutput("[SOCKS] Already running.");
            return;
        }

        serverSocket = new ServerSocket(port, 50);
        executor = Executors.newCachedThreadPool();
        running = true;

        executor.submit(() -> {
            api.logging().logToOutput("[SOCKS] Accept loop started on port " + port);
            while (running && !serverSocket.isClosed()) {
                try {
                    Socket client = serverSocket.accept();
                    executor.submit(() -> handleClient(client));
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
    public void stop() {
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

        api.logging().logToOutput("[SOCKS] Stopped.");
    }

    // ==================== Per-connection handling ====================

    private void handleClient(Socket client) {
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

            try {
                target = new Socket();
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

        if (password != null && !password.isEmpty()) {
            if (!offersUserPass) {
                out.write(new byte[]{SOCKS_VERSION, AUTH_NO_ACCEPTABLE});
                out.flush();
                return false;
            }
            out.write(new byte[]{SOCKS_VERSION, AUTH_USER_PASS});
            out.flush();
            return doUserPassAuth(in, out, client);
        } else {
            out.write(new byte[]{SOCKS_VERSION, AUTH_NONE});
            out.flush();
            return true;
        }
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

        String suppliedPassword = new String(passwd, StandardCharsets.UTF_8);
        boolean ok = password.equals(suppliedPassword);

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
        readByte(in); // RSV
        int atyp = readByte(in);

        if (ver != SOCKS_VERSION) return null;

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
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }

        // One direction ended — force-close both sockets so the other pump thread unblocks.
        closeQuietly(a);
        closeQuietly(b);

        try {
            t2.join(2000);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
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
        } catch (IOException ignored) {
            // Expected once either side closes the connection.
        }
    }

    // ==================== Helpers ====================

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
