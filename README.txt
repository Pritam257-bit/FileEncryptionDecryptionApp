File Encryption/Decryption Application
This Java-based desktop application allows users to encrypt and decrypt files using AES (Advanced Encryption Standard). It provides a simple GUI for file handling operations, making it easy to secure and access encrypted data.

**Features
Encrypt Files: Encrypt files using AES encryption with a 16-byte key.
Decrypt Files: Decrypt previously encrypted files.
User-Friendly Interface: Simple GUI for selecting files and performing encryption/decryption operations.
Error Handling: Handles common errors related to encryption and decryption.
**Prerequisites
Java 17: Ensure Java 17 is installed on your system.
Maven: Used for managing dependencies and building the project.


Project Structure
Directory Layout:
src/main/java/com/example/encryption/: Contains encryption and decryption logic.

AESEncryption.java: Manages AES encryption and decryption.
src/main/java/com/example/ui/: Contains the GUI components.

FileEncryptionApp.java: Main class for the GUI.
src/main/java/com/example/utils/: Contains utility classes.

FileUtils.java: Handles file read/write operations.
CryptoUtils.java: Contains additional cryptographic utilities.
src/test/java/com/example/encryption/: Contains test classes.

AESEncryptionTest.java: Tests for AES encryption and decryption.
src/main/resources/: Configuration and resource files.

pom.xml: Maven build configuration file.

Usage
Running the Application:
Start the Application:

Launch the application through IntelliJ IDEA or using Maven as described above.
Select a File:

Click on the “Select File” button to browse and select a file for encryption or decryption.
Encrypt a File:

Click the “Encrypt” button to encrypt the selected file. The encrypted file will be saved with an .enc extension.
Decrypt a File:

Click the “Decrypt” button to decrypt the selected file. The decrypted file will be saved with a .dec extension.
Key Handling:
The application uses a hardcoded encryption key (1234567890123456). For production use, consider implementing secure key management.