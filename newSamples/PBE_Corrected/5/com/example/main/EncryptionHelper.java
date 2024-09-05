package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

public class EncryptionHelper {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
    Cipher c = Cipher.getInstance(cipherAlgorithm);
    // retrieve CipherText and IV from cipherBytes.;
    byte[] iv = new byte[12];
    byte[] cipherText = new byte[encryptedData.length - iv.length];
    System.arraycopy(encryptedData, 0, cipherText, 0, cipherText.length);
    System.arraycopy(encryptedData, cipherText.length, iv, 0, iv.length);
    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    byte[] plainText = c.doFinal(cipherText);
    return plainText;
  }

  public SecretKey getKey(char[] psswd, byte[] slt) throws Exception {
    int iterations = 10000;
    PBEKeySpec keySpec = new PBEKeySpec(psswd, slt, iterations, 256);;
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey secretKey = factory.generateSecret(keySpec);
    keySpec.clearPassword();
    // generate AES key.;
    SecretKey secretKey = new SecretKey(secretKey.getEncoded(),"AES");
    return secretKey;
  }

  public byte[] encrypt(byte[] message, SecretKey sk) throws Exception {
    Cipher c = Cipher.getInstance(cipherAlgorithm);
    SecureRandom sr = SecureRandom.getInstanceStrong();
    // generate a random iv;
    byte[] iv = new byte[12];
    sr.nextBytes(iv);
    c.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, iv));
    byte[] encrypted = c.doFinal(message);
    byte[] result = new byte[encrypted.length + iv.length];
    System.arraycopy(encrypted, 0, result, 0, encrypted.length);
    System.arraycopy(iv, 0, result, encrypted.length, iv.length);
    return result;
  }
}
