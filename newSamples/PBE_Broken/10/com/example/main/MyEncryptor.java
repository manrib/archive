package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class MyEncryptor {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] decrypt(byte[] cipherText, SecretKey key) throws Exception {
    Cipher c = Cipher.getInstance(cipherAlgorithm);
    // retrieve CipherText and IV from cipherBytes.;
    byte[] iv = new byte[12];
    byte[] cipherText = new byte[cipherText.length - iv.length];
    System.arraycopy(cipherText, 0, cipherText, 0, cipherText.length);
    System.arraycopy(cipherText, cipherText.length, iv, 0, iv.length);
    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    byte[] plainText = c.doFinal(cipherText);
    return plainText;
  }

  public byte[] Enc(byte[] message, SecretKey sk) throws Exception {
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

  public SecretKey getKey(byte[] psswd) throws Exception {
    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
    // generate random salt;
    byte[] digest = messageDigest.digest(psswd);
    byte[] passkey = new byte[16];
    for (int i=0; i<16; ++i) {
      passkey[i] = digest[i];
    }
    // generate AES key;
    SecretKey secretKey = new SecretKey(passkey,"AES");
    return secretKey;
  }
}
