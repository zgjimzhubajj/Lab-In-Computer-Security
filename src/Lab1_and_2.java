package src;

import java.security.*;
import java.security.cert.CertificateFactory;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

    public class Lab1_and_2 {
        public static void main(String[] args) throws Exception {
            //Lab 1: Task 1
            // Define file paths
            String keystorePath = "lab1Store";
            String encryptedFilePath = "ciphertext.enc";
            String signaturePath1 = "ciphertext.enc.sig1";
            String signaturePath2 = "ciphertext.enc.sig2";
            String certificatePath = "lab1Sign.cert";
            String macFilePath1 = "ciphertext.mac1.txt";
            String macFilePath2 = "ciphertext.mac2.txt";


            // Read the encrypted file content
            byte[] encryptedFileContent = Files.readAllBytes(Paths.get(encryptedFilePath));

            // Assuming each part is 128 bytes
            byte[] rsaEncryptedKey = Arrays.copyOfRange(encryptedFileContent, 0, 128);
            byte[] rsaEncryptedIV = Arrays.copyOfRange(encryptedFileContent, 128, 256);
            byte[] rsaEncryptedHmacKey = Arrays.copyOfRange(encryptedFileContent, 256, 384);
            byte[] aesEncryptedData = Arrays.copyOfRange(encryptedFileContent, 384, encryptedFileContent.length);

            // Load the keystore
            //To decrypt key1 and iv we need a private key
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keystoreFis = new FileInputStream(keystorePath)) {
                keyStore.load(keystoreFis, "lab1StorePass".toCharArray());
            }
            //Get the private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());

            //Lab 1: Task 2
            // RSA decryption to obtain the keys: key1 Iv and 2
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] key1 = rsaCipher.doFinal(rsaEncryptedKey);
            byte[] iv = rsaCipher.doFinal(rsaEncryptedIV);
            byte[] key2 = rsaCipher.doFinal(rsaEncryptedHmacKey);

            // AES decryption to obtain the plain text from the keys which are key 1 and iv
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, "AES"), new IvParameterSpec(iv));
            byte[] plaintext = aesCipher.doFinal(aesEncryptedData);

            //Lab 2: Task 3
            // Read HMACs from files
            // Read MAC strings and convert them to byte arrays
            String mac1String = new String(Files.readAllBytes(Paths.get(macFilePath1)));
            String mac2String = new String(Files.readAllBytes(Paths.get(macFilePath2)));
            byte[] hmac1 = hexStringToByteArray(mac1String);
            byte[] hmac2 = hexStringToByteArray(mac2String);

            // Verify HMAC
            boolean hmacVerified1 = verifyHmac(plaintext, key2, hmac1);
            boolean hmacVerified2 = verifyHmac(plaintext, key2, hmac2);

            //Lab 2: Task 4
            // Read public key from certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            PublicKey publicKey = cf.generateCertificate(new FileInputStream(certificatePath)).getPublicKey();

            // Read signatures
            byte[] signature1 = Files.readAllBytes(Paths.get(signaturePath1));
            byte[] signature2 = Files.readAllBytes(Paths.get(signaturePath2));

            // Verify signatures
            boolean signatureVerified1 = verifySignature(plaintext, signature1, publicKey);
            boolean signatureVerified2 = verifySignature(plaintext, signature2, publicKey);

            // Output results
            System.out.println("Decrypted message: " + new String(plaintext));
            System.out.println("HMAC 1 verification: " + hmacVerified1);
            System.out.println("HMAC 2 verification: " + hmacVerified2);
            System.out.println("Signature 1 verification: " + signatureVerified1);
            System.out.println("Signature 2 verification: " + signatureVerified2);
        }

        private static boolean verifyHmac(byte[] data, byte[] key, byte[] expectedHmac) throws Exception {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            byte[] computedHmac = mac.doFinal(data);
            return Arrays.equals(computedHmac, expectedHmac);
        }

        private static byte[] hexStringToByteArray(String s) {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16));
            }
            return data;
        }

        private static boolean verifySignature(byte[] plaintext, byte[] signature, PublicKey publicKey) throws Exception {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(publicKey);
            sig.update(plaintext);
            return sig.verify(signature);
        }
    }
