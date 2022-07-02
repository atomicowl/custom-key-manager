package com.keystore;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("UNIT_TEST")
class CustomAliasX509ExtendedKeyManagerTest {

    @Test
    void getClientAliases_is_delegated() {
        final KeyStore keyStore = mock(KeyStore.class);

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        final String[] certs = {"client-cert-1", "client-cert-2"};
        when(x509KeyManager.getClientAliases(any(), any())).thenReturn(certs);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        final String[] actual = customAliasX509ExtendedKeyManager.getClientAliases(null, null);
        assertEquals(certs, actual);
    }

    @Test
    void chooseClientAlias_returns_specified_cert_alias() throws Exception {
        final KeyStore keyStore = mock(KeyStore.class);

        doReturn(true).when(keyStore).containsAlias("client-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        final String actual = customAliasX509ExtendedKeyManager.chooseClientAlias(null, null, null);
        assertEquals("client-cert-1", actual);
    }

    @Test
    void chooseClientAlias_throws_exception_if_specified_cert_is_not_in_the_keystore() throws Exception {
        final KeyStore keyStore = mock(KeyStore.class);

        doReturn(false).when(keyStore).containsAlias("client-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        when(x509KeyManager.chooseEngineClientAlias(any(), any(), any())).thenReturn("client-cert-1");


        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        Exception exception = null;
        try {
            customAliasX509ExtendedKeyManager.chooseClientAlias(null, null, null);
        } catch (final Exception ex) {
            exception = ex;
        }

        assertEquals("certificate with alias client-cert-1 not found", exception.getMessage());
    }

    @Test
    void chooseClientAlias_throws_exception_if_keystore_is_not_initialized() throws Exception {
        final KeyStore keyStore = mock(KeyStore.class);

        doThrow(new RuntimeException("keystore uninitialized"))
                .when(keyStore).containsAlias("client-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        when(x509KeyManager.chooseEngineClientAlias(any(), any(), any())).thenReturn("client-cert-1");


        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        Exception exception = null;
        try {
            customAliasX509ExtendedKeyManager.chooseClientAlias(null, null, null);
        } catch (final Exception ex) {
            exception = ex;
        }

        assertEquals("keystore uninitialized", exception.getMessage());
    }

    @Test
    void getServerAliases_is_delegated() {
        final KeyStore keyStore = mock(KeyStore.class);

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        final String[] certs = {"client-cert-1", "client-cert-2"};
        when(x509KeyManager.getServerAliases(any(), any())).thenReturn(certs);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        final String[] actual = customAliasX509ExtendedKeyManager.getServerAliases(null, null);
        assertEquals(certs, actual);
    }

    @Test
    void chooseServerAlias_returns_specified_cert_alias() throws KeyStoreException {
        final KeyStore keyStore = mock(KeyStore.class);

        doReturn(true).when(keyStore).containsAlias("server-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, null, "server-cert-1");

        final String actual = customAliasX509ExtendedKeyManager.chooseServerAlias(null, null, null);
        assertEquals("server-cert-1", actual);
    }

    @Test
    void chooseServerAlias_throws_exception_if_specified_cert_is_not_in_the_keystore() throws Exception {
        final KeyStore keyStore = mock(KeyStore.class);

        doReturn(false).when(keyStore).containsAlias("server-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        when(x509KeyManager.chooseServerAlias(any(), any(), any())).thenReturn("server-cert-1");


        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, null, "server-cert-1");

        Exception exception = null;
        try {
            customAliasX509ExtendedKeyManager.chooseServerAlias(null, null, null);
        } catch (final Exception ex) {
            exception = ex;
        }

        assertEquals("certificate with alias server-cert-1 not found", exception.getMessage());
    }

    @Test
    void chooseServerAlias_throws_exception_if_keystore_is_not_initialized() throws Exception {
        final KeyStore keyStore = mock(KeyStore.class);

        doThrow(new RuntimeException("keystore uninitialized"))
                .when(keyStore).containsAlias("server-cert-1");

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        when(x509KeyManager.chooseServerAlias(any(), any(), any())).thenReturn("server-cert-1");


        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, null, "server-cert-1");

        Exception exception = null;
        try {
            customAliasX509ExtendedKeyManager.chooseServerAlias(null, null, null);
        } catch (final Exception ex) {
            exception = ex;
        }

        assertEquals("keystore uninitialized", exception.getMessage());
    }

    @Test
    void getCertificateChain_is_delegated() {
        final KeyStore keyStore = mock(KeyStore.class);

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        final X509Certificate[] certs = { mock(X509Certificate.class), mock(X509Certificate.class) };
        when(x509KeyManager.getCertificateChain(any())).thenReturn(certs);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        final X509Certificate[] actual = customAliasX509ExtendedKeyManager.getCertificateChain(null);
        assertEquals(certs, actual);
    }

    @Test
    void getPrivateKey_is_delegated() {
        final KeyStore keyStore = mock(KeyStore.class);

        final X509ExtendedKeyManager x509KeyManager = mock(X509ExtendedKeyManager.class);
        final PrivateKey certs = mock(PrivateKey.class);
        when(x509KeyManager.getPrivateKey(any())).thenReturn(certs);

        final CustomAliasX509ExtendedKeyManager customAliasX509ExtendedKeyManager =
                new CustomAliasX509ExtendedKeyManager(
                        keyStore, x509KeyManager, "client-cert-1", null);

        final PrivateKey actual = customAliasX509ExtendedKeyManager.getPrivateKey(null);
        assertEquals(certs, actual);
    }
}