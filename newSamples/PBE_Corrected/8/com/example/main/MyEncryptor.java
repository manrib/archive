package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

public class MyEncryptor {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] decrypt(byte[] encryptedData, SecretKey sk) {
    try {
      Cipher c = Cipher.getInstance(cipherAlgorithm);
      // retrieve CipherText and IV from cipherBytes.;
      byte[] iv = new byte[12];
      byte[] cipherText = new byte[encryptedData.length - iv.length];
      System.arraycopy(encryptedData, 0, cipherText, 0, cipherText.length);
      System.arraycopy(encryptedData, cipherText.length, iv, 0, iv.length);
      c.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(128, iv));
      byte[] plainText = c.doFinal(cipherText);
      return plainText;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public SecretKey getKey(char[] password, byte[] slt) {
    try {
      int iterations = 10000;
      PBEKeySpec pbeKeySpec = new PBEKeySpec(password, slt, iterations, 256);;
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      SecretKey secretKey = factory.generateSecret(pbeKeySpec);
      pbeKeySpec.clearPassword();
      // generate AES key.;
      SecretKey sk = new SecretKey(secretKey.getEncoded(),"AES");
      return sk;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] encrypt(byte[] data, SecretKey sk) {
    try {
      Cipher c = Cipher.getInstance(cipherAlgorithm);
      SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      // generate a random iv;
      byte[] iv = new byte[12];
      secureRandom.nextBytes(iv);
      c.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, iv));
      byte[] encrypted = c.doFinal(data);
      byte[] result = new byte[encrypted.length + iv.length];
      System.arraycopy(encrypted, 0, result, 0, encrypted.length);
      System.arraycopy(iv, 0, result, encrypted.length, iv.length);
      return result;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }
}
