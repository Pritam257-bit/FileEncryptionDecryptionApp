package com.example.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class KeyManagement {

    // Method to generate an AES key
    public SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize); // 128, 192, or 256 bits
        return keyGen.generateKey();
    }

    // Method to generate an RSA key pair
    public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keySize);
        return keyPairGen.generateKeyPair();
    }

    // Method to convert a key to a Base64 string (for storage)
    public String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public String keyToString(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    // Method to convert a Base64 string back to a SecretKey (AES example)
    public SecretKey stringToAESKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new javax.crypto.spec.SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
