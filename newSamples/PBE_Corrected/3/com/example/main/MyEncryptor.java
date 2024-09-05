package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

public class MyEncryptor {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] Dec(byte[] encryptedData, SecretKey sk) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    // retrieve CipherText and IV from cipherBytes.;
    byte[] ivBytes = new byte[12];
    byte[] cipherText = new byte[encryptedData.length - ivBytes.length];
    System.arraycopy(encryptedData, 0, cipherText, 0, cipherText.length);
    System.arraycopy(encryptedData, cipherText.length, ivBytes, 0, ivBytes.length);
    cipher.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(128, iv));
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }

  public byte[] encrypt(byte[] message, SecretKey sk) throws Exception {
    Cipher c = Cipher.getInstance(cipherAlgorithm);
    SecureRandom secureRandom = SecureRandom.getInstanceStrong();
    // generate a random iv;
    byte[] ivBytes = new byte[12];
    secureRandom.nextBytes(ivBytes);
    c.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, ivBytes));
    byte[] encrypted = c.doFinal(message);
    byte[] result = new byte[encrypted.length + ivBytes.length];
    System.arraycopy(encrypted, 0, result, 0, encrypted.length);
    System.arraycopy(ivBytes, 0, result, encrypted.length, ivBytes.length);
    return result;
  }

  public SecretKey get_key(char[] password, byte[] salt) throws Exception {
    int iterations = 10000;
    PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterations, 256);;
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey secretKey = factory.generateSecret(pbeKeySpec);
    pbeKeySpec.clearPassword();
    // generate AES key.;
    SecretKey sk = new SecretKey(secretKey.getEncoded(),"AES");
    return sk;
  }
}
