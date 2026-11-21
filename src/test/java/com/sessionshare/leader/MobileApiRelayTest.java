package com.sessionshare.leader;

import com.sessionshare.follower.SelectiveSocksProxy;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static com.sessionshare.leader.RelayIntegrationTest.LOOPBACK;
import static com.sessionshare.leader.RelayIntegrationTest.api;
import static com.sessionshare.leader.RelayIntegrationTest.port;
import static org.junit.jupiter.api.Assertions.*;

/** Models the desktop's outgoing SOCKS connection to a laptop relay using a local HTTPS API. */
class MobileApiRelayTest {
    @Test @Timeout(30)
    void relaysMobileApiPostOverTls(@TempDir Path directory) throws Exception {
        SSLContext tls = localTls(directory);
        HttpsServer target = HttpsServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
        target.setHttpsConfigurator(new HttpsConfigurator(tls));
        target.createContext("/mobile/sync", exchange -> {
            try (exchange) {
                byte[] body = exchange.getRequestBody().readAllBytes();
                boolean valid = exchange.getRequestMethod().equals("POST")
                        && "application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type"));
                exchange.sendResponseHeaders(valid ? 201 : 400, body.length);
                exchange.getResponseBody().write(body);
            }
        });
        String password = "local-test-relay";
        SocksRelayServer leader = new SocksRelayServer(api());
        SelectiveSocksProxy follower = new SelectiveSocksProxy(api());
        try {
            target.start();
            leader.setPassword(password);
            leader.setAllowedScope("localhost");
            leader.start(0, LOOPBACK);
            follower.start(0, LOOPBACK.getHostAddress(), port(leader), password, "localhost");
            int apiPort = target.getAddress().getPort();
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", port(follower)));
            try (Socket socket = new Socket(proxy)) {
                socket.connect(InetSocketAddress.createUnresolved("localhost", apiPort), 4000);
                try (SSLSocket https = (SSLSocket) tls.getSocketFactory().createSocket(socket, "localhost", apiPort, true)) {
                    https.setSoTimeout(4000);
                    SSLParameters options = https.getSSLParameters();
                    options.setEndpointIdentificationAlgorithm("HTTPS");
                    https.setSSLParameters(options);
                    byte[] body = "{\"message\":\"Hello, 世界!\"}".getBytes(StandardCharsets.UTF_8);
                    String headers = "POST /mobile/sync HTTP/1.1\r\nHost: localhost:" + apiPort
                            + "\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n";
                    https.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));
                    https.getOutputStream().write(body);
                    byte[] response = https.getInputStream().readAllBytes();
                    // One character per byte preserves the byte offset after the response headers.
                    String envelope = new String(response, StandardCharsets.ISO_8859_1);
                    assertTrue(envelope.startsWith("HTTP/1.1 201 "));
                    int headerEnd = envelope.indexOf("\r\n\r\n");
                    assertTrue(headerEnd >= 0);
                    assertArrayEquals(body, Arrays.copyOfRange(response, headerEnd + 4, response.length));
                    assertEquals(1, leader.getTotalConnections());
                }
            }
        } finally {
            follower.stop();
            leader.stop();
            target.stop(0);
        }
    }

    /** Generate a one-day localhost certificate and trust it only within this test's TLS context. */
    private static SSLContext localTls(Path directory) throws Exception {
        Path storeFile = directory.resolve("localhost.p12");
        String password = "local-test-store";
        String executable = System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool";
        Path keytool = Path.of(System.getProperty("java.home"), "bin", executable);
        Path log = directory.resolve("keytool.log");
        Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-noprompt",
                "-alias", "localhost", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "1",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-keystore", storeFile.toString(),
                "-storetype", "PKCS12", "-storepass", password).redirectErrorStream(true)
                .redirectOutput(log.toFile()).start();
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "keytool timed out");
            assertEquals(0, process.exitValue(), () -> "keytool failed; see " + log);
        } finally {
            process.destroyForcibly();
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream stream = Files.newInputStream(storeFile)) {
            store.load(stream, password.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password.toCharArray());
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
        return context;
    }
}
