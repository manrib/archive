package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CodeEncryptor {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] Dec(byte[] encryptedData, SecretKey key) {
    try {
      Cipher cipher = Cipher.getInstance(cipherAlgorithm);
      // retrieve CipherText and IV from cipherBytes.;
      byte[] ivBytes = new byte[12];
      byte[] cipherText = new byte[encryptedData.length - ivBytes.length];
      System.arraycopy(encryptedData, 0, cipherText, 0, cipherText.length);
      System.arraycopy(encryptedData, cipherText.length, ivBytes, 0, ivBytes.length);
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
      byte[] plainText = cipher.doFinal(cipherText);
      return plainText;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public SecretKey get_key(byte[] password) {
    try {
      MessageDigest mds = MessageDigest.getInstance("MD5");
      // generate random salt;
      byte[] digest = mds.digest(password);
      byte[] passkey = new byte[16];
      for (int i=0; i<16; ++i) {
        passkey[i] = digest[i];
      }
      // generate AES key;
      SecretKey secretKey = new SecretKey(passkey,"AES");
      return secretKey;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] encrypt(byte[] message, SecretKey key) {
    try {
      Cipher cipher = Cipher.getInstance(cipherAlgorithm);
      SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      // generate a random iv;
      byte[] ivBytes = new byte[12];
      secureRandom.nextBytes(ivBytes);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, ivBytes));
      byte[] encrypted = cipher.doFinal(message);
      byte[] result = new byte[encrypted.length + ivBytes.length];
      System.arraycopy(encrypted, 0, result, 0, encrypted.length);
      System.arraycopy(ivBytes, 0, result, encrypted.length, ivBytes.length);
      return result;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }
}
