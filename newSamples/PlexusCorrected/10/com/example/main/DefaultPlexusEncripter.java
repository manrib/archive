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

  public String decryptDecorated(String cipherText, char[] password) {
    try {
      if ( StringUtils.isEmpty( cipherText ) ) {
        return cipherText;
      }
      if ( isEncryptedString( cipherText ) ) {
        return decrypt( unDecorate( cipherText ), password );
      }
      return decrypt(cipherText,password);
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] generateIV() {
    try {
      SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      byte[] ivBytes = new byte[IV_SIZE];
      secureRandom.nextBytes(ivBytes);
      return ivBytes;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  private Cipher init(char[] password, byte[] salt, byte[] ivBytes, boolean encrypt) {
    try {
      int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
      PBEKeySpec keySpec = new PBEKeySpec(password,salt, ITERATION_COUNT,KEY_SIZE);;
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM,SECURITY_PROVIDER);
      SecretKey sk = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
      keySpec.clearPassword();
      Cipher ce = Cipher.getInstance(CIPHER_ALGORITHM);
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH,ivBytes);
      ce.init(mode,sk,gcmParameterSpec);
      return ce;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String decrypt(String cipherText, char[] password) {
    try {
      byte[] decodedData = Base64.getDecoder().decode(cipherText);
      byte[] salt = new byte[SALT_SIZE];
      System.arraycopy(decodedData, 0, salt, 0, SALT_SIZE);
      byte[] ivBytes = new byte[IV_SIZE];
      System.arraycopy(decodedData, SALT_SIZE, ivBytes, 0, IV_SIZE);
      byte[] encrypted = new byte[decodedData.length - SALT_SIZE - IV_SIZE];
      System.arraycopy(decodedData, SALT_SIZE + IV_SIZE, encrypted, 0, encrypted.length);
      Cipher dc = init(password,salt,ivBytes,false);
      byte[] utf8 = dc.doFinal(encrypted);
      return new String(utf8, STRING_ENCODING);
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public byte[] generateSalt() {
    try {
      SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      byte[] salt = new byte[SALT_SIZE];
      secureRandom.nextBytes(salt);
      return salt;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String encrypt(String data, char[] password) {
    try {
      byte[] salt = generateSalt();
      byte[] ivBytes = generateIV();
      Cipher ce = init(password,salt,ivBytes,true);
      // Encode the string into bytes using utf-8;
      byte[] utf8 = data.getBytes(STRING_ENCODING);
      byte[] encrypted = ce.doFinal(utf8);
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      outputStream.write(salt);
      outputStream.write(ivBytes);
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

  public String encryptAndDecorate(String data, char[] password) {
    try {
       return decorate( encrypt( data, password ) );
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

  public void initialize() {
    try {
      Security.addProvider(new BouncyCastleProvider());;
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }
}
