package com.keystore.tools;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificateGenerator {

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

