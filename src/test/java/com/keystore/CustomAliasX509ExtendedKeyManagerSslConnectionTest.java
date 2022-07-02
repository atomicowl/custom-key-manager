package com.keystore;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("INTEGRATION_TEST")
public class CustomAliasX509ExtendedKeyManagerSslConnectionTest {

    private final CertificateGenerator serverCertificateGenerator = new CertificateGenerator();
    private final char[] EMPTY_PASSWORD = new char[]{};

    @Test
    public void establish_ssl_connection_with_single_certificate_added_to_server_keystore_and_clients_truststore() throws Exception {

        final X509Certificate cert = serverCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Application,O=My Organisation,L=My City,C=DE");

        final KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("cert-1", serverCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{cert});

        final KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("cert-1", cert);

        final KeyStore emptyKeyStore = KeyStore.getInstance("JKS");
        emptyKeyStore.load(null, null);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(serverKeyStore, emptyKeyStore, executorService, false);
        final SslClient sslClient = new SslClient(emptyKeyStore, clientTrustStore, null);

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        sslServer.start(0, (String message, Throwable ex) -> {
            resultHolder.set(new Result<>(message, ex));
            latch.countDown();
        });

        sslClient.sendMessage("localhost", sslServer.activePort, "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("Hello", resultHolder.get().getSuccessOrThrowException());
    }

    @Test
    public void unable_to_establish_sslConnection_if_mutual_tls_is_enabled_but_certificate_is_not_added_into_clients_keystore() throws Exception {

        final X509Certificate cert = serverCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Application,O=My Organisation,L=My City,C=DE");

        final KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("cert-1", serverCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{cert});

        final KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("cert-1", cert);

        final KeyStore emptyKeyStore = KeyStore.getInstance("JKS");
        emptyKeyStore.load(null, null);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(serverKeyStore, emptyKeyStore, executorService, true);
        final SslClient sslClient = new SslClient(emptyKeyStore, clientTrustStore, null);

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        sslServer.start(0, (String message, Throwable ex) -> {
            resultHolder.set(new Result<>(message, ex));
            latch.countDown();
        });

        sslClient.sendMessage("localhost", sslServer.activePort, "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("javax.net.ssl.SSLHandshakeException: Empty client certificate chain",
            resultHolder.get().getError().getCause().getCause().toString());
    }

    @Test
    public void establish_sslConnection_via_mutual_tls_when_certificate_is_added_into_clients_keystore() throws Exception {
        final CertificateGenerator serverCertificateGenerator = new CertificateGenerator();
        final X509Certificate serverCert = serverCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Application,O=My Organisation,L=My City,C=DE");

        final CertificateGenerator clientCertificateGenerator = new CertificateGenerator();
        final X509Certificate clientCert = clientCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Other Application,O=My Organisation,L=My City,C=DE");

        //configure SERVER keystore and truststore
        final KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("servercert-1", serverCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{serverCert});

        final KeyStore serverTrustStore = KeyStore.getInstance("JKS");
        serverTrustStore.load(null, null);
        serverTrustStore.setCertificateEntry("clientcert-1", clientCert);

        //configure CLIENT keystore and truststore
        final KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("clientcert-1", clientCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{clientCert});

        final KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("servercert-1", serverCert);


        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(serverKeyStore, serverTrustStore, executorService, true);
        final SslClient sslClient = new SslClient(clientKeyStore, clientTrustStore, null);

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        sslServer.start(0, (String message, Throwable ex) -> {
            resultHolder.set(new Result<>(message, ex));
            latch.countDown();
        });

        sslClient.sendMessage("localhost", sslServer.activePort, "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("Hello", resultHolder.get().getSuccessOrThrowException());
    }

    @Test
    public void unable_to_establish_sslConnection_via_mutual_tls_when_MULTIPLE_certificates_are_added_into_clients_keystore() throws Exception {
        final CertificateGenerator serverCertificateGenerator = new CertificateGenerator();
        final X509Certificate serverCert = serverCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Application,O=My Organisation,L=My City,C=DE");

        final CertificateGenerator clientCertificateGenerator = new CertificateGenerator();
        final X509Certificate clientCert = clientCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Other Application,O=My Organisation,L=My City,C=DE");

        //Additional client cert is generated
        final CertificateGenerator clientCertificateGenerator2 = new CertificateGenerator();
        final X509Certificate clientCert2 = clientCertificateGenerator2.generateSelfSignedCertificate(
            "CN=My Other Application,O=My Organisation,L=My City,C=DE");

        //configure SERVER keystore and truststore
        final KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("serverCert-1", serverCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{serverCert});

        final KeyStore serverTrustStore = KeyStore.getInstance("JKS");
        serverTrustStore.load(null, null);
        serverTrustStore.setCertificateEntry("clientcert-1", clientCert);

        //configure CLIENT keystore and truststore
        final KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("clientcert-1", clientCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{clientCert});
        clientKeyStore.setKeyEntry("clientcert-2", clientCertificateGenerator2.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{clientCert2});

        final KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("servercert-1", serverCert);


        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(serverKeyStore, serverTrustStore, executorService, true);
        final SslClient sslClient = new SslClient(clientKeyStore, clientTrustStore, null);

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        sslServer.start(0, (String message, Throwable ex) -> {
            resultHolder.set(new Result<>(message, ex));
            latch.countDown();
        });

        sslClient.sendMessage("localhost", sslServer.activePort, "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("javax.net.ssl.SSLHandshakeException: PKIX path validation failed: java.security.cert.CertPathValidatorException: signature check failed",
            resultHolder.get().getError().getCause().getCause().toString());
    }

    @Test
    public void establish_sslConnection_via_mutual_tls_when_MULTIPLE_certificates_are_added_into_clients_keystore_using_custom_key_manager() throws Exception {
        final CertificateGenerator serverCertificateGenerator = new CertificateGenerator();
        final X509Certificate serverCert = serverCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Application,O=My Organisation,L=My City,C=DE");

        final CertificateGenerator clientCertificateGenerator = new CertificateGenerator();
        final X509Certificate clientCert = clientCertificateGenerator.generateSelfSignedCertificate(
            "CN=My Other Application,O=My Organisation,L=My City,C=DE");

        //Additional client cert is generated
        final CertificateGenerator clientCertificateGenerator2 = new CertificateGenerator();
        final X509Certificate clientCert2 = clientCertificateGenerator2.generateSelfSignedCertificate(
            "CN=My Other Application,O=My Organisation,L=My City,C=DE");

        //configure SERVER keystore and truststore
        final KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("servercert-1", serverCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{serverCert});

        final KeyStore serverTrustStore = KeyStore.getInstance("JKS");
        serverTrustStore.load(null, null);
        serverTrustStore.setCertificateEntry("clientcert-1", clientCert);

        //configure CLIENT keystore and truststore
        final KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("clientcert-1", clientCertificateGenerator.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{clientCert});
        clientKeyStore.setKeyEntry("clientCert-2", clientCertificateGenerator2.getPrivateKey(), EMPTY_PASSWORD, new Certificate[]{clientCert2});

        final KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("servercert-1", serverCert);


        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(serverKeyStore, serverTrustStore, executorService, true);
        final SslClient sslClient = new SslClient(clientKeyStore, clientTrustStore, "clientcert-1");

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        sslServer.start(0, (String message, Throwable ex) -> {
            resultHolder.set(new Result<>(message, ex));
            latch.countDown();
        });

        sslClient.sendMessage("localhost", sslServer.activePort, "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("Hello", resultHolder.get().getSuccessOrThrowException());
    }

    public class SslClient {

        private final SSLSocketFactory socketFactory;

        public SslClient(
            final KeyStore keyStore,
            final KeyStore trustStore,
            final String clientCertAlias
        ) {
            try {
                final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, EMPTY_PASSWORD);

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

        public void sendMessage(final String host, final int port, final String message) {
            try (final SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, port)) {
                socket.setUseClientMode(true);
                socket.startHandshake();
                final OutputStream out = socket.getOutputStream();
                final OutputStreamWriter writer = new OutputStreamWriter(out);
                try (final BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
                    bufferedWriter.write(message);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public class SslServer {

        private final ExecutorService executorService;
        private final SSLServerSocketFactory serverSocketFactory;

        private final boolean isClientAuthenticationRequired;
        private int activePort;

        public SslServer(
            final KeyStore keyStore,
            final KeyStore trustStore,
            final ExecutorService executorService,
            final boolean isClientAuthenticationRequired
        ) {
            this.executorService = executorService;
            this.isClientAuthenticationRequired = isClientAuthenticationRequired;

            try {
                final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, EMPTY_PASSWORD);

                final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);

                final SSLContext serverSslContext = SSLContext.getInstance("TLS");
                serverSslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

                this.serverSocketFactory = serverSslContext.getServerSocketFactory();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        public void start(final Integer port, final BiConsumer<String, Throwable> afterMessageConsumed) {
            try {
                @SuppressWarnings("resource") final SSLServerSocket sslSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
                sslSocket.setNeedClientAuth(isClientAuthenticationRequired);

                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    try {
                        sslSocket.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }));

                activePort = sslSocket.getLocalPort();
                CompletableFuture
                    .supplyAsync(
                        () -> {
                            final StringBuilder builder = new StringBuilder();
                            try (SSLSocket socket = (SSLSocket) sslSocket.accept()) {
                                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                                String line;
                                while ((line = reader.readLine()) != null) {
                                    builder.append(line);
                                }
                            } catch (final Exception ex) {
                                throw new RuntimeException(ex);
                            }
                            return builder.toString();
                        }, executorService
                    )
                    .orTimeout(10, TimeUnit.SECONDS)
                    .whenComplete(afterMessageConsumed);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class CertificateGenerator {

        private final CertAndKeyGen certAndKeyGen;

        public CertificateGenerator() {
            try {
                this.certAndKeyGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
                this.certAndKeyGen.generate(2048);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }

        public X509Certificate generateSelfSignedCertificate(final String certDetails) {
            try {
                // valid for one year
                final long validSecs = (long) 365 * 24 * 60 * 60;
                return certAndKeyGen.getSelfCertificate(
                    // enter your details according to your application
                    new X500Name(certDetails), validSecs);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public PrivateKey getPrivateKey() {
            return certAndKeyGen.getPrivateKey();
        }
    }

    public static class Result<SUCCESS> {

        private final SUCCESS success;

        private final Throwable error;

        public Result(final SUCCESS success, final Throwable error) {
            this.success = success;
            this.error = error;
        }

        public SUCCESS getSuccessOrThrowException() {
            if (error != null) {
                throw new RuntimeException(error);
            }
            return success;
        }

        public Throwable getError() {
            return error;
        }
    }
}
