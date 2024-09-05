package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class EncryptionHelper {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] Dec(byte[] cipherText, SecretKey key) {
    try {
      Cipher c = Cipher.getInstance(cipherAlgorithm);
      // retrieve CipherText and IV from cipherBytes.;
      byte[] ivBytes = new byte[12];
      byte[] cipherText = new byte[cipherText.length - ivBytes.length];
      System.arraycopy(cipherText, 0, cipherText, 0, cipherText.length);
      System.arraycopy(cipherText, cipherText.length, ivBytes, 0, ivBytes.length);
      c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
      byte[] plainText = c.doFinal(cipherText);
      return plainText;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] Enc(byte[] message, SecretKey key) {
    try {
      Cipher c = Cipher.getInstance(cipherAlgorithm);
      SecureRandom sr = SecureRandom.getInstanceStrong();
      // generate a random iv;
      byte[] ivBytes = new byte[12];
      sr.nextBytes(ivBytes);
      c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, ivBytes));
      byte[] encrypted = c.doFinal(message);
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

  public SecretKey get_key(byte[] psswd) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("MD5");
      // generate random salt;
      byte[] digest = messageDigest.digest(psswd);
      byte[] passkey = new byte[16];
      for (int i=0; i<16; ++i) {
        passkey[i] = digest[i];
      }
      // generate AES key;
      SecretKey sk = new SecretKey(passkey,"AES");
      return sk;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }
}
