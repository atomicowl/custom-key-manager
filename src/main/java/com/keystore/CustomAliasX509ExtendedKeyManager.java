package com.keystore;

import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CustomAliasX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private final KeyStore keyStore;
    private final X509ExtendedKeyManager delegate;

    private final String clientAlias;

    private final String serverAlias;

    public CustomAliasX509ExtendedKeyManager(
            final KeyStore keyStore,
            final X509ExtendedKeyManager delegate,
            final String clientAlias,
            final String serverAlias
    ) {
        this.keyStore = keyStore;
        this.delegate = delegate;
        this.clientAlias = clientAlias;
        this.serverAlias = serverAlias;
    }

    @Override
    public String[] getClientAliases(final String keyType, final Principal[] issuers) {
        return delegate.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(final String[] keyType, final Principal[] issuers, final Socket socket) {
        try {
            if (keyStore.containsAlias(clientAlias)) {
                return clientAlias;
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        throw new RuntimeException("certificate with alias " + clientAlias + " not found");
    }

    @Override
    public String[] getServerAliases(final String keyType, final Principal[] issuers) {
        return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(final String keyType, final Principal[] issuers, final Socket socket) {
        try {
            if (keyStore.containsAlias(serverAlias)) {
                return serverAlias;
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        throw new RuntimeException("certificate with alias " + serverAlias + " not found");
    }

    @Override
    public X509Certificate[] getCertificateChain(final String alias) {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) {
        return delegate.getPrivateKey(alias);
    }
}
