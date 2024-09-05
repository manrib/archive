package com.example.main;

import java.io.ByteArrayOutputStream;
import java.lang.Exception;
import java.lang.String;
import java.lang.System;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64Encoder;

public class DefaultPlexusEncripter {
  private static final String ENCRYPTED_STRING_DECORATION_START = "Start_";

  private static final String ENCRYPTED_STRING_DECORATION_STOP = "End_";

  private static final String SECURITY_PROVIDER = "BC";

  private static final int SALT_SIZE = 8;

  private static final String STRING_ENCODING = "UTF8";

  protected String algorithm = "PBEWithSHAAnd128BitRC4";

  protected int iterationCount = 23;

  public String decryptDecorated(String encryptedData, String password) {
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

  void XXX1() {
  }

  private Cipher init(String password, byte[] salt, boolean encrypt) {
    try {
      int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
      KeySpec keySpec = new PBEKeySpec(password.toCharArray());;
      SecretKey secretKey = SecretKeyFactory.getInstance(algorithm, SECURITY_PROVIDER).generateSecret(keySpec);
      Cipher encryptSipher = Cipher.getInstance(algorithm);
      PBEParameterSpec paramSpec = new PBEParameterSpec(salt,iterationCount);
      encryptSipher.init(mode,secretKey,paramSpec);
      return encryptSipher;
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

  public String Dec(String encryptedData, String password) {
    try {
      if ( StringUtils.isEmpty( encryptedData ) ) return encryptedData;
      Base64Encoder decode = new Base64Encoder();
      ByteArrayOutputStream baus = new ByteArrayOutputStream();
      byte[] res = baus.toByteArray();
      int saltLen = res[0] & 0x00ff;
      if ( saltLen != SALT_SIZE )  throw new Exception("corrupted structure");
      if ( res.length < ( saltLen + 2 ) ) throw new Exception("corrupted structure");
      byte[] salt = new byte[saltLen];
      System.arraycopy( res, 1, salt, 0, saltLen );
      int decLen = res.length - saltLen - 1;
      if ( decLen < 1 ) throw new Exception( "encryptedStringCorruptedSize" );
      byte[] dec = new byte[decLen];
      System.arraycopy( res, saltLen + 1, dec, 0, decLen );
      // Decrypt;
      Cipher decryptCipher = init(password,salt,false);
      byte[] utf8 = decryptCipher.doFinal( dec );
      return new String( utf8, "UTF8" );
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  private byte[] genSalt(int saltSize) {
    try {
      SecureRandom sr = new SecureRandom();
      sr.setSeed(System.currentTimeMillis());
      return sr.generateSeed(saltSize);
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String encrypt(String message, String password) {
    try {
      byte[] salt = genSalt(SALT_SIZE);
      Cipher encryptSipher = init(password,salt,true);
      // Encode the string into bytes using utf-8;
      byte[] utf8 = message.getBytes(STRING_ENCODING);
      byte[] enc = encryptSipher.doFinal(utf8);
      // Encode bytes to base64 to get a string;
      Base64Encoder b64 = new Base64Encoder();
      byte saltLen = (byte) ( salt.length & 0x00ff );
      int encLen = enc.length;
      byte[] res = new byte[salt.length + encLen + 1];
      res[0] = saltLen;
      System.arraycopy( salt, 0, res, 1, saltLen );
      System.arraycopy( enc, 0, res, saltLen + 1, encLen );
      ByteArrayOutputStream bout = new ByteArrayOutputStream( res.length * 2 );
      b64.encode( res, 0, res.length, bout );
      return bout.toString( STRING_ENCODING );
    } catch (Exception e) {
      // TODO handle exception;
      e.printStackTrace();
      return null;
    }
  }

  public String encryptAndDecorate(String message, String password) {
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
