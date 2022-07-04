package com.keystore.tools;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public class SslServer {

    private final ExecutorService executorService;
    private final SSLServerSocketFactory serverSocketFactory;

    private final boolean isClientAuthenticationRequired;
    private final Handler handler;
    private final int timeoutSeconds;
    private int activePort;

    public SslServer(
        final KeyStore keyStore,
        final char[] keyStorePassword,
        final KeyStore trustStore,
        final ExecutorService executorService,
        final boolean isClientAuthenticationRequired,
        final Handler handler,
        final int timeoutSeconds
    ) {
        this.executorService = executorService;
        this.isClientAuthenticationRequired = isClientAuthenticationRequired;
        this.handler = handler;
        this.timeoutSeconds = timeoutSeconds;

        try {
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword);

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            final SSLContext serverSslContext = SSLContext.getInstance("TLS");
            serverSslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            this.serverSocketFactory = serverSslContext.getServerSocketFactory();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public void start(final Integer port) {
        try {
            @SuppressWarnings("resource") final SSLServerSocket sslSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
            sslSocket.setNeedClientAuth(isClientAuthenticationRequired);
            activePort = sslSocket.getLocalPort();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    sslSocket.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }));

            CompletableFuture
                .runAsync(
                    () -> {
                        try (SSLSocket socket = (SSLSocket) sslSocket.accept()) {
                            this.handler.handle(socket.getInputStream(), socket.getOutputStream());
                        } catch (final Exception ex) {
                            throw new RuntimeException(ex);
                        }
                    }, executorService
                )
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public int getActivePort() {
        return activePort;
    }
}
