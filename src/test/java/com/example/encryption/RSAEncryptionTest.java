package com.example.encryption;

import com.example.utils.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class RSAEncryptionTest {

    private File inputFile;
    private File encryptedFile;
    private File decryptedFile;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Initialize files for testing
        inputFile = new File("test_input_rsa.txt");
        encryptedFile = new File("test_input_rsa.txt.enc");
        decryptedFile = new File("decrypted_test_input_rsa.txt");

        // Write some data to the input file
        Files.write(inputFile.toPath(), "This is a test for RSA".getBytes());

        // Generate the key pair
        keyPair = CryptoUtils.generateRSAKeyPair();
    }

    @Test
    void testRSAEncryption() throws Exception {
        // Perform RSA encryption
        CryptoUtils.encryptRSA(inputFile, encryptedFile, keyPair.getPublic());

        // Ensure the encrypted file exists and is not empty
        assertTrue(encryptedFile.exists());
        assertTrue(encryptedFile.length() > 0);
    }

    @Test
    void testRSADecryption() throws Exception {
        // First, encrypt the file using RSA
        CryptoUtils.encryptRSA(inputFile, encryptedFile, keyPair.getPublic());

        // Then, decrypt the file using RSA
        CryptoUtils.decryptRSA(encryptedFile, decryptedFile, keyPair.getPrivate());

        // Ensure the decrypted file matches the original input
        assertTrue(decryptedFile.exists());
        assertArrayEquals(Files.readAllBytes(inputFile.toPath()), Files.readAllBytes(decryptedFile.toPath()));
    }
}
