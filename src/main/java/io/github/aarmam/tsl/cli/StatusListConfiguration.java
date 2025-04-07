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
}
