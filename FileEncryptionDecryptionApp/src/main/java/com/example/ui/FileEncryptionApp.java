package com.example.ui;

import com.example.encryption.AESEncryption;
import com.example.utils.FileUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptionApp extends JFrame {

    private JButton selectFileButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private JFileChooser fileChooser;
    private File selectedFile;
    private final String encryptionKey = "1234567890123456"; // 16 bytes key for AES

    public FileEncryptionApp() {
        setTitle("File Encryption/Decryption App");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        fileChooser = new JFileChooser();
        selectFileButton = new JButton("Select File");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        JPanel panel = new JPanel();
        panel.add(selectFileButton);
        panel.add(encryptButton);
        panel.add(decryptButton);

        add(panel);

        selectFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFile != null) {
                    try {
                        byte[] fileContent = FileUtils.readFileToByteArray(selectedFile);
                        byte[] encryptedContent = AESEncryption.encrypt(fileContent, encryptionKey);
                        FileUtils.writeByteArrayToFile(new File(selectedFile.getAbsolutePath() + ".enc"), encryptedContent);
                        JOptionPane.showMessageDialog(null, "File encrypted successfully.");
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        JOptionPane.showMessageDialog(null, "Encryption failed: " + ex.getMessage());
                    }
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFile != null) {
                    try {
                        byte[] fileContent = FileUtils.readFileToByteArray(selectedFile);
                        byte[] decryptedContent = AESEncryption.decrypt(fileContent, encryptionKey);
                        FileUtils.writeByteArrayToFile(new File(selectedFile.getAbsolutePath().replace(".enc", ".dec")), decryptedContent);
                        JOptionPane.showMessageDialog(null, "File decrypted successfully.");
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        JOptionPane.showMessageDialog(null, "Decryption failed: " + ex.getMessage());
                    }
                }
            }
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            FileEncryptionApp app = new FileEncryptionApp();
            app.setVisible(true);
        });
    }
}
