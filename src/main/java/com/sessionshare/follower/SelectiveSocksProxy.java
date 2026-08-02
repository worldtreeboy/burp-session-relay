package com.sessionshare.follower;

import burp.api.montoya.MontoyaApi;
import com.sessionshare.util.ScopeMatcher;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Loopback-only SOCKS5 proxy used by the follower. Target hosts are connected through
 * the leader's authenticated SOCKS5 relay; all other hosts are connected directly.
 */
public final class SelectiveSocksProxy {
    private final MontoyaApi api;
    private final Set<Socket> openSockets = ConcurrentHashMap.newKeySet();
    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private volatile String leaderHost = "127.0.0.1";
    private volatile int leaderPort = 1080;
    private volatile String password = "";
    private volatile String scope = "";

    public SelectiveSocksProxy(MontoyaApi api) { this.api = api; }
    public boolean isRunning() { return running; }

    public synchronized void start(int localPort, String leaderHost, int leaderPort,
                                   String password, String scope) throws IOException {
        if (running) return;
        if (password == null || password.isBlank()) throw new IllegalArgumentException("Password is required");
        if (scope == null || scope.isBlank()) throw new IllegalArgumentException("Target scope is required");
        this.leaderHost = leaderHost;
        this.leaderPort = leaderPort;
        this.password = password;
        this.scope = scope;
        serverSocket = new ServerSocket();
        serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), localPort), 50);
        executor = Executors.newFixedThreadPool(32);
        running = true;
        executor.submit(this::acceptLoop);
        api.logging().logToOutput("[Selective SOCKS] Listening on 127.0.0.1:" + localPort);
    }

    public synchronized void stop() {
        running = false;
        close(serverSocket);
        for (Socket socket : openSockets) close(socket);
        openSockets.clear();
        if (executor != null) executor.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                openSockets.add(client);
                executor.submit(() -> handle(client));
            } catch (IOException e) {
                if (running) api.logging().logToError("[Selective SOCKS] Accept failed: " + e.getMessage());
            }
        }
    }

    private void handle(Socket client) {
        Socket destination = null;
        try {
            client.setSoTimeout(10_000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            if (read(in) != 5) return;
            int methods = read(in);
            readFully(in, methods);
            out.write(new byte[]{5, 0});
            out.flush();

            if (read(in) != 5) return;
            int command = read(in);
            read(in);
            int addressType = read(in);
            HostPort requested = readAddress(in, addressType);
            if (command != 1 || requested == null) {
                reply(out, 7);
                return;
            }

            boolean viaLeader = ScopeMatcher.matchesHost(requested.host, scope);
            destination = viaLeader ? connectViaLeader(requested) : connectDirect(requested);
            openSockets.add(destination);
            reply(out, 0);
            client.setSoTimeout(0);
            destination.setSoTimeout(0);
            api.logging().logToOutput("[Selective SOCKS] " + requested.host + ":" + requested.port
                    + (viaLeader ? " via leader" : " direct"));
            pump(client, destination);
        } catch (Exception e) {
            try { reply(client.getOutputStream(), 4); } catch (Exception ignored) {}
            api.logging().logToError("[Selective SOCKS] Connection failed: " + e.getMessage());
        } finally {
            openSockets.remove(client);
            if (destination != null) openSockets.remove(destination);
            close(client);
            close(destination);
        }
    }

    private Socket connectDirect(HostPort target) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(target.host, target.port), 10_000);
        return socket;
    }

    private Socket connectViaLeader(HostPort target) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(leaderHost, leaderPort), 10_000);
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        out.write(new byte[]{5, 1, 2});
        out.flush();
        if (read(in) != 5 || read(in) != 2) throw new IOException("Leader rejected SOCKS authentication method");
        byte[] user = "sessionshare".getBytes(StandardCharsets.UTF_8);
        byte[] pass = password.getBytes(StandardCharsets.UTF_8);
        if (pass.length > 255) throw new IOException("Password is too long for SOCKS authentication");
        out.write(1); out.write(user.length); out.write(user); out.write(pass.length); out.write(pass); out.flush();
        if (read(in) != 1 || read(in) != 0) throw new IOException("Leader SOCKS authentication failed");
        byte[] host = target.host.getBytes(StandardCharsets.UTF_8);
        if (host.length > 255) throw new IOException("Hostname is too long");
        out.write(new byte[]{5, 1, 0, 3, (byte) host.length});
        out.write(host); out.write((target.port >>> 8) & 0xff); out.write(target.port & 0xff); out.flush();
        if (read(in) != 5 || read(in) != 0) throw new IOException("Leader could not reach target");
        read(in); int atyp = read(in); skipAddress(in, atyp); readFully(in, 2);
        return socket;
    }

    private HostPort readAddress(InputStream in, int type) throws IOException {
        String host;
        if (type == 1) host = InetAddress.getByAddress(readFully(in, 4)).getHostAddress();
        else if (type == 3) host = new String(readFully(in, read(in)), StandardCharsets.UTF_8);
        else if (type == 4) host = InetAddress.getByAddress(readFully(in, 16)).getHostAddress();
        else return null;
        return new HostPort(host, (read(in) << 8) | read(in));
    }

    private void skipAddress(InputStream in, int type) throws IOException {
        if (type == 1) readFully(in, 4);
        else if (type == 3) readFully(in, read(in));
        else if (type == 4) readFully(in, 16);
        else throw new IOException("Invalid SOCKS address type");
    }

    private void pump(Socket a, Socket b) throws InterruptedException {
        Thread one = new Thread(() -> copy(a, b), "SessionShare-selective-socks");
        Thread two = new Thread(() -> copy(b, a), "SessionShare-selective-socks");
        one.setDaemon(true); two.setDaemon(true); one.start(); two.start();
        one.join(); close(a); close(b); two.join(2_000);
    }

    private void copy(Socket from, Socket to) {
        try {
            from.getInputStream().transferTo(to.getOutputStream());
        } catch (IOException ignored) {}
    }

    private static void reply(OutputStream out, int status) throws IOException {
        out.write(new byte[]{5, (byte) status, 0, 1, 0, 0, 0, 0, 0, 0}); out.flush();
    }
    private static int read(InputStream in) throws IOException {
        int value = in.read(); if (value < 0) throw new EOFException(); return value;
    }
    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] bytes = in.readNBytes(length);
        if (bytes.length != length) throw new EOFException();
        return bytes;
    }
    private static void close(Closeable value) {
        if (value != null) try { value.close(); } catch (IOException ignored) {}
    }
    private record HostPort(String host, int port) {}
}
