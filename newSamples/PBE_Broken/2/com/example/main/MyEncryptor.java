package com.example.main;

import java.lang.Exception;
import java.lang.String;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class MyEncryptor {
  private static String cipherAlgorithm = "AES/GCM/NoPadding";

  public byte[] Dec(byte[] cipherText, SecretKey sk) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    // retrieve CipherText and IV from cipherBytes.;
    byte[] ivBytes = new byte[12];
    byte[] cipherText = new byte[cipherText.length - ivBytes.length];
    System.arraycopy(cipherText, 0, cipherText, 0, cipherText.length);
    System.arraycopy(cipherText, cipherText.length, ivBytes, 0, ivBytes.length);
    cipher.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(128, iv));
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }

  public byte[] Enc(byte[] message, SecretKey sk) throws Exception {
    Cipher c = Cipher.getInstance(cipherAlgorithm);
    SecureRandom sr = SecureRandom.getInstanceStrong();
    // generate a random iv;
    byte[] ivBytes = new byte[12];
    sr.nextBytes(ivBytes);
    c.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, ivBytes));
    byte[] encrypted = c.doFinal(message);
    byte[] result = new byte[encrypted.length + ivBytes.length];
    System.arraycopy(encrypted, 0, result, 0, encrypted.length);
    System.arraycopy(ivBytes, 0, result, encrypted.length, ivBytes.length);
    return result;
  }

  public SecretKey get_key(byte[] psswd) throws Exception {
    MessageDigest mds = MessageDigest.getInstance("MD5");
    // generate random salt;
    byte[] digest = mds.digest(psswd);
    byte[] passkey = new byte[16];
    for (int i=0; i<16; ++i) {
      passkey[i] = digest[i];
    }
    // generate AES key;
    SecretKey secretKey = new SecretKey(passkey,"AES");
    return secretKey;
  }
}
