package com.example.main;

import java.io.ByteArrayOutputStream;
import java.lang.Exception;
import java.lang.String;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DefaultPlexusEncripter {
  private static final String ENCRYPTED_STRING_DECORATION_START = "Start_";

  private static final String ENCRYPTED_STRING_DECORATION_STOP = "End_";

  private static final String SECURITY_PROVIDER = "BC";

  private static final int SALT_SIZE = 16;

  private static final int IV_SIZE = 12;

  private static final String STRING_ENCODING = StandardCharsets.UTF_8.name();

  private static final int ITERATION_COUNT = 65536;

  private static final int KEY_SIZE = 256;

  private static final int GCM_TAG_LENGTH = 128;

  protected String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

  protected String ALGORITHM = "PBEWithHmacSHA256AndAES_256";

  public String unDecorate(String str) {
    try {
      if (isEncryptedString( str )) {
        throw new Exception("bad input");
      }
      int start = str.indexOf( ENCRYPTED_STRING_DECORATION_START );
      int stop = str.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
      return str.substring( start + 1, stop );
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String decryptDecorated(String encryptedData, char[] password) {
    try {
      if ( StringUtils.isEmpty( encryptedData ) ) {
        return encryptedData;
      }
      if ( isEncryptedString( encryptedData ) ) {
        return Dec( unDecorate( encryptedData ), password );
      }
      return Dec(encryptedData,password);
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] generateIV() {
    try {
      SecureRandom sr = SecureRandom.getInstanceStrong();
      byte[] iv = new byte[IV_SIZE];
      sr.nextBytes(iv);
      return iv;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  private Cipher init(char[] password, byte[] salt, byte[] iv, boolean encrypt) {
    try {
      int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
      PBEKeySpec keySpec = new PBEKeySpec(password,salt, ITERATION_COUNT,KEY_SIZE);;
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM,SECURITY_PROVIDER);
      SecretKey secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
      keySpec.clearPassword();
      Cipher encryptSipher = Cipher.getInstance(CIPHER_ALGORITHM);
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH,iv);
      encryptSipher.init(mode,secretKey,gcmParameterSpec);
      return encryptSipher;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String Dec(String encryptedData, char[] password) {
    try {
      byte[] decodedData = Base64.getDecoder().decode(encryptedData);
      byte[] salt = new byte[SALT_SIZE];
      System.arraycopy(decodedData, 0, salt, 0, SALT_SIZE);
      byte[] iv = new byte[IV_SIZE];
      System.arraycopy(decodedData, SALT_SIZE, iv, 0, IV_SIZE);
      byte[] encrypted = new byte[decodedData.length - SALT_SIZE - IV_SIZE];
      System.arraycopy(decodedData, SALT_SIZE + IV_SIZE, encrypted, 0, encrypted.length);
      Cipher decryptCipher = init(password,salt,iv,false);
      byte[] utf8 = decryptCipher.doFinal(encrypted);
      return new String(utf8, STRING_ENCODING);
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] genSalt() {
    try {
      SecureRandom sr = SecureRandom.getInstanceStrong();
      byte[] salt = new byte[SALT_SIZE];
      sr.nextBytes(salt);
      return salt;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String encrypt(String message, char[] password) {
    try {
      byte[] salt = genSalt();
      byte[] iv = generateIV();
      Cipher encryptSipher = init(password,salt,iv,true);
      // Encode the string into bytes using utf-8;
      byte[] utf8 = message.getBytes(STRING_ENCODING);
      byte[] encrypted = encryptSipher.doFinal(utf8);
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      outputStream.write(salt);
      outputStream.write(iv);
      outputStream.write(encrypted);
      return  Base64.getEncoder().encodeToString(outputStream.toByteArray());
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public boolean isEncryptedString(String str) {
    try {
      if ( StringUtils.isEmpty( str ) ) {
        return false;
      }
      int start = str.indexOf( ENCRYPTED_STRING_DECORATION_START );
      int stop = str.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
      if ( start != -1 && stop != -1 && stop > start + 1 ) {
        return true;
      }
      return false;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String encryptAndDecorate(String message, char[] password) {
    try {
       return decorate( encrypt( message, password ) );
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public void initialize() {
    try {
      Security.addProvider(new BouncyCastleProvider());;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String decorate(String str) {
    try {
      return ENCRYPTED_STRING_DECORATION_START + ( str == null ? "" : str ) + ENCRYPTED_STRING_DECORATION_STOP;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }
}
