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

  public String unDecorate(String s) throws Exception {
    if (isEncryptedString( s )) {
      throw new Exception("bad input");
    }
    int start = s.indexOf( ENCRYPTED_STRING_DECORATION_START );
    int stop = s.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
    return s.substring( start + 1, stop );
  }

  public String encrypt(String data, String psswd) throws Exception {
    byte[] slt = genSalt(SALT_SIZE);
    Cipher ce = init(psswd,slt,true);
    // Encode the string into bytes using utf-8;
    byte[] utf8 = data.getBytes(STRING_ENCODING);
    byte[] enc = ce.doFinal(utf8);
    // Encode bytes to base64 to get a string;
    Base64Encoder b64 = new Base64Encoder();
    byte saltLen = (byte) ( slt.length & 0x00ff );
    int encLen = enc.length;
    byte[] res = new byte[slt.length + encLen + 1];
    res[0] = saltLen;
    System.arraycopy( slt, 0, res, 1, saltLen );
    System.arraycopy( enc, 0, res, saltLen + 1, encLen );
    ByteArrayOutputStream bout = new ByteArrayOutputStream( res.length * 2 );
    b64.encode( res, 0, res.length, bout );
    return bout.toString( STRING_ENCODING );
  }

  public void initialize() throws Exception {
    Security.addProvider(new BouncyCastleProvider());;
  }

  public String decorate(String s) throws Exception {
    return ENCRYPTED_STRING_DECORATION_START + ( s == null ? "" : s ) + ENCRYPTED_STRING_DECORATION_STOP;
  }

  private byte[] genSalt(int saltSize) throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(System.currentTimeMillis());
    return secureRandom.generateSeed(saltSize);
  }

  public String decrypt(String encryptedData, String psswd) throws Exception {
    if ( StringUtils.isEmpty( encryptedData ) ) return encryptedData;
    Base64Encoder decode = new Base64Encoder();
    ByteArrayOutputStream baus = new ByteArrayOutputStream();
    byte[] res = baus.toByteArray();
    int saltLen = res[0] & 0x00ff;
    if ( saltLen != SALT_SIZE )  throw new Exception("corrupted structure");
    if ( res.length < ( saltLen + 2 ) ) throw new Exception("corrupted structure");
    byte[] slt = new byte[saltLen];
    System.arraycopy( res, 1, slt, 0, saltLen );
    int decLen = res.length - saltLen - 1;
    if ( decLen < 1 ) throw new Exception( "encryptedStringCorruptedSize" );
    byte[] dec = new byte[decLen];
    System.arraycopy( res, saltLen + 1, dec, 0, decLen );
    // Decrypt;
    Cipher decryptCipher = init(psswd,slt,false);
    byte[] utf8 = decryptCipher.doFinal( dec );
    return new String( utf8, "UTF8" );
  }

  void XXX1() {
  }

  public String decryptDecorated(String encryptedData, String psswd) throws Exception {
    if ( StringUtils.isEmpty( encryptedData ) ) {
      return encryptedData;
    }
    if ( isEncryptedString( encryptedData ) ) {
      return decrypt( unDecorate( encryptedData ), psswd );
    }
    return decrypt(encryptedData,psswd);
  }

  public boolean isEncryptedString(String s) throws Exception {
    if ( StringUtils.isEmpty( s ) ) {
      return false;
    }
    int start = s.indexOf( ENCRYPTED_STRING_DECORATION_START );
    int stop = s.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
    if ( start != -1 && stop != -1 && stop > start + 1 ) {
      return true;
    }
    return false;
  }

  public String encryptAndDecorate(String data, String psswd) throws Exception {
     return decorate( encrypt( data, psswd ) );
  }

  private Cipher init(String psswd, byte[] slt, boolean encrypt) throws Exception {
    int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    KeySpec keySpec = new PBEKeySpec(psswd.toCharArray());;
    SecretKey secretKey = SecretKeyFactory.getInstance(algorithm, SECURITY_PROVIDER).generateSecret(keySpec);
    Cipher ce = Cipher.getInstance(algorithm);
    PBEParameterSpec paramSpec = new PBEParameterSpec(slt,iterationCount);
    ce.init(mode,secretKey,paramSpec);
    return ce;
  }
}
