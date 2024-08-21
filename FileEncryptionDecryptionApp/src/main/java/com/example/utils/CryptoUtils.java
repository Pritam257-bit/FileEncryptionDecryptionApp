package com.example.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    private static final String AES = "AES";
    private static final String RSA = "RSA";

    // AES Key Generation
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(256); // AES-256 key size
        return keyGen.generateKey();
    }

    // RSA Key Pair Generation
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        keyGen.initialize(2048); // RSA-2048 key size
        return keyGen.generateKeyPair();
    }

    // Save AES Key to File
    public static void saveKeyToFile(Key key, File file) throws IOException {
        byte[] keyBytes = key.getEncoded();
        String keyBase64 = Base64.getEncoder().encodeToString(keyBytes);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(keyBase64);
        }
    }

    // Load AES Key from File
    public static SecretKey loadKeyFromFile(File file) throws IOException {
        byte[] keyBytes = Base64.getDecoder().decode(new String(Files.readAllBytes(file.toPath())));
        return new SecretKeySpec(keyBytes, AES);
    }

    // AES File Encryption
    public static void encrypt(File inputFile, File outputFile, Key key) throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, AES, key, inputFile, outputFile);
    }

    // AES File Decryption
    public static void decrypt(File inputFile, File outputFile, Key key) throws Exception {
        doCrypto(Cipher.DECRYPT_MODE, AES, key, inputFile, outputFile);
    }

    // RSA File Encryption
    public static void encryptRSA(File inputFile, File outputFile, PublicKey publicKey) throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, RSA, publicKey, inputFile, outputFile);
    }

    // RSA File Decryption
    public static void decryptRSA(File inputFile, File outputFile, PrivateKey privateKey) throws Exception {
        doCrypto(Cipher.DECRYPT_MODE, RSA, privateKey, inputFile, outputFile);
    }

    // Utility method for performing encryption/decryption
    private static void doCrypto(int cipherMode, String algorithm, Key key, File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(cipherMode, key);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            outputStream.write(outputBytes);
        }
    }

    // Save RSA Public Key to File
    public static void saveRSAPublicKey(PublicKey publicKey, File file) throws IOException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(x509EncodedKeySpec.getEncoded());
        }
    }

    // Load RSA Public Key from File
    public static PublicKey loadRSAPublicKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(spec);
    }

    // Save RSA Private Key to File
    public static void saveRSAPrivateKey(PrivateKey privateKey, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(privateKey.getEncoded());
        }
    }

    // Load RSA Private Key from File
    public static PrivateKey loadRSAPrivateKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        return KeyFactory.getInstance(RSA).generatePrivate(new X509EncodedKeySpec(keyBytes));
    }
}
