package com.example.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileUtils {

    // Reads file content to byte array
    public static byte[] readFileToByteArray(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }

    // Writes byte array to file
    public static void writeByteArrayToFile(File file, byte[] data) throws IOException {
        Files.write(file.toPath(), data);
    }
}
