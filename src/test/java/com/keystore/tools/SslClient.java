package com.keystore.tools;

import com.keystore.CustomAliasX509ExtendedKeyManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.SecureRandom;

public class SslClient {

    private final SSLSocketFactory socketFactory;

    public SslClient(
        final KeyStore keyStore,
        final char[] keyStorePassword,
        final KeyStore trustStore,
        final String clientCertAlias
    ) {
        try {
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword);

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            final SSLContext serverSslContext = SSLContext.getInstance("TLS");
            if (clientCertAlias == null) {
                serverSslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            } else {
                final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                    new CustomAliasX509ExtendedKeyManager(
                        keyStore,
                        (X509ExtendedKeyManager) keyManagerFactory.getKeyManagers()[0],
                        clientCertAlias,
                        null);
                serverSslContext.init(
                    new KeyManager[]{customAliasX509ExtendedKeyManager},
                    trustManagerFactory.getTrustManagers(),
                    new SecureRandom());
            }

            this.socketFactory = serverSslContext.getSocketFactory();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public String sendMessage(final String host, final int port, final String message) {
        try (
            final SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, port);
            final BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            final PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)
        ) {
            socket.setUseClientMode(true);
            socket.startHandshake();

            writer.println(message);

            return reader.readLine();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}



