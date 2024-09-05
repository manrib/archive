package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class EncryptionHelper {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    // retrieve CipherText and IV from cipherBytes.;
    byte[] ivBytes = new byte[12];
    byte[] cipherText = new byte[encryptedData.length - ivBytes.length];
    System.arraycopy(encryptedData, 0, cipherText, 0, cipherText.length);
    System.arraycopy(encryptedData, cipherText.length, ivBytes, 0, ivBytes.length);
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }

  public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    SecureRandom secureRandom = SecureRandom.getInstanceStrong();
    // generate a random iv;
    byte[] ivBytes = new byte[12];
    secureRandom.nextBytes(ivBytes);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, ivBytes));
    byte[] encrypted = cipher.doFinal(data);
    byte[] result = new byte[encrypted.length + ivBytes.length];
    System.arraycopy(encrypted, 0, result, 0, encrypted.length);
    System.arraycopy(ivBytes, 0, result, encrypted.length, ivBytes.length);
    return result;
  }

  public SecretKey getKey(byte[] password) throws Exception {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
    // generate random salt;
    byte[] digest = messageDigest.digest(password);
    byte[] passkey = new byte[16];
    for (int i=0; i<16; ++i) {
      passkey[i] = digest[i];
    }
    // generate AES key;
    SecretKey secretKey = new SecretKey(passkey,"AES");
    return secretKey;
  }
}
