package com.example.encryption;

import com.example.utils.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

class AESEncryptionTest {

    private File inputFile;
    private File encryptedFile;
    private File decryptedFile;
    private Key secretKey;

    @BeforeEach
    void setUp() throws Exception {
        // Initialize files for testing
        inputFile = new File("test_input.txt");
        encryptedFile = new File("test_input.txt.enc");
        decryptedFile = new File("decrypted_test_input.txt");

        // Write some data to the input file
        Files.write(inputFile.toPath(), "This is a test".getBytes());

        // Generate the secret key
        secretKey = CryptoUtils.generateKey();
    }

    @Test
    void testEncryption() throws Exception {
        // Perform encryption
        CryptoUtils.encrypt(inputFile, encryptedFile, secretKey);

        // Ensure the encrypted file exists and is not empty
        assertTrue(encryptedFile.exists());
        assertTrue(encryptedFile.length() > 0);
    }

    @Test
    void testDecryption() throws Exception {
        // First, encrypt the file
        CryptoUtils.encrypt(inputFile, encryptedFile, secretKey);

        // Then, decrypt the file
        CryptoUtils.decrypt(encryptedFile, decryptedFile, secretKey);

        // Ensure the decrypted file matches the original input
        assertTrue(decryptedFile.exists());
        assertArrayEquals(Files.readAllBytes(inputFile.toPath()), Files.readAllBytes(decryptedFile.toPath()));
    }
}
