package io.github.aarmam.tsl.cli;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@Configuration
public class StatusListConfiguration {

    @Bean
    public Key signingKey(SslBundles sslBundles) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        SslBundle bundle = sslBundles.getBundle("status-list-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        SslBundleKey key = bundle.getKey();
        String password = key.getPassword();
        return keyStore.getKey(key.getAlias(), password != null ? password.toCharArray() : null);
    }

    /**
     * The certificate the Status List Tokens are signed under, so the signing command can
     * report on the extended key usage described in Section 10 of the specification.
     */
    @Bean
    public X509Certificate signingCertificate(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("status-list-issuer");
        Certificate certificate = bundle.getStores().getKeyStore().getCertificate(bundle.getKey().getAlias());
        return certificate instanceof X509Certificate x509 ? x509 : null;
    }
}
