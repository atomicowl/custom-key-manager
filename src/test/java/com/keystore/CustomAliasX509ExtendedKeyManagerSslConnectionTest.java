package com.keystore;

import com.keystore.tools.CertificateGenerator;
import com.keystore.tools.HandlerImpl;
import com.keystore.tools.Result;
import com.keystore.tools.SslClient;
import com.keystore.tools.SslServer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("INTEGRATION_TEST")
public class CustomAliasX509ExtendedKeyManagerSslConnectionTest {

    private final CertificateGenerator serverCertificateGenerator = new CertificateGenerator();
    private final char[] EMPTY_PASSWORD = new char[]{};

    private final int DEFAULT_TIMEOUT_SECONDS = 10;

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

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(
            serverKeyStore,
            EMPTY_PASSWORD,
            emptyKeyStore,
            executorService,
            false,
            new HandlerImpl((Result<String> result) -> {
                resultHolder.set(result);
                latch.countDown();
            }),
            DEFAULT_TIMEOUT_SECONDS
        );
        final SslClient sslClient = new SslClient(
            emptyKeyStore, EMPTY_PASSWORD, clientTrustStore, null);

        sslServer.start(0);
        sslClient.sendMessage("localhost", sslServer.getActivePort(), "Hello");

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

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(
            serverKeyStore,
            EMPTY_PASSWORD,
            emptyKeyStore,
            executorService,
            true,
            new HandlerImpl((Result<String> result) -> {
                resultHolder.set(result);
                latch.countDown();
            }),
            DEFAULT_TIMEOUT_SECONDS
        );
        final SslClient sslClient = new SslClient(
            emptyKeyStore, EMPTY_PASSWORD, clientTrustStore, null);

        sslServer.start(0);
        sslClient.sendMessage("localhost", sslServer.getActivePort(), "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("javax.net.ssl.SSLHandshakeException: Empty client certificate chain",
            resultHolder.get().getError().toString());
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

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(
            serverKeyStore,
            EMPTY_PASSWORD,
            serverTrustStore,
            executorService,
            true,
            new HandlerImpl((Result<String> result) -> {
                resultHolder.set(result);
                latch.countDown();
            }),
            DEFAULT_TIMEOUT_SECONDS
        );
        final SslClient sslClient = new SslClient(
            clientKeyStore, EMPTY_PASSWORD, clientTrustStore, null);

        sslServer.start(0);
        sslClient.sendMessage("localhost", sslServer.getActivePort(), "Hello");

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

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(
            serverKeyStore,
            EMPTY_PASSWORD,
            serverTrustStore,
            executorService,
            true,
            new HandlerImpl((Result<String> result) -> {
                resultHolder.set(result);
                latch.countDown();
            }),
            DEFAULT_TIMEOUT_SECONDS
        );
        final SslClient sslClient = new SslClient(
            clientKeyStore, EMPTY_PASSWORD, clientTrustStore, null);

        sslServer.start(0);
        sslClient.sendMessage("localhost", sslServer.getActivePort(), "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("PKIX path validation failed: java.security.cert.CertPathValidatorException: signature check failed",
            resultHolder.get().getError().getMessage());
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

        final AtomicReference<Result<String>> resultHolder = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        final ExecutorService executorService = Executors.newSingleThreadExecutor();
        final SslServer sslServer = new SslServer(
            serverKeyStore,
            EMPTY_PASSWORD,
            serverTrustStore,
            executorService,
            true,
            new HandlerImpl((Result<String> result) -> {
                resultHolder.set(result);
                latch.countDown();
            }),
            DEFAULT_TIMEOUT_SECONDS
        );

        final SslClient sslClient = new SslClient(
            clientKeyStore, EMPTY_PASSWORD, clientTrustStore, "clientcert-1");

        sslServer.start(0);
        sslClient.sendMessage("localhost", sslServer.getActivePort(), "Hello");

        //noinspection ResultOfMethodCallIgnored
        latch.await(10, TimeUnit.SECONDS);
        executorService.shutdown();
        //noinspection ResultOfMethodCallIgnored
        executorService.awaitTermination(10, TimeUnit.SECONDS);

        assertEquals("Hello", resultHolder.get().getSuccessOrThrowException());
    }
}
