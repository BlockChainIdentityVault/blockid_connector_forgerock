package org.forgerock.openam.auth.nodes;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.Arrays;

public class BlockIDECDSAHelper {
  private Cipher _cx;	
  
  private byte[] _key;
   
  private byte[] _iv;
  
  private enum EncryptMode {
    ENCRYPT, DECRYPT;
  }
  
  public BlockIDECDSAHelper() throws NoSuchAlgorithmException, NoSuchPaddingException {
    this._cx = Cipher.getInstance("AES/GCM/NoPadding");
    this._key = new byte[32];
    this._iv = new byte[16];
  }
  
  public byte[] encryptDecrypt(String inputText, String encryptionKey, EncryptMode mode, String initVector) throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    int len = (encryptionKey.getBytes("UTF-8")).length; 
    if ((encryptionKey.getBytes("UTF-8")).length > this._key.length)
      len = this._key.length; 
    int ivlength = (initVector.getBytes("UTF-8")).length;
    if ((initVector.getBytes("UTF-8")).length > this._iv.length)
      ivlength = this._iv.length; 
    System.arraycopy(Base64.getDecoder().decode(encryptionKey.getBytes()), 0, this._key, 0, len);
    System.arraycopy(initVector.getBytes("UTF-8"), 0, this._iv, 0, ivlength);
    SecretKeySpec keySpec = new SecretKeySpec(this._key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(this._iv);
    if (mode.equals(EncryptMode.ENCRYPT)) {
      this._cx.init(1, keySpec, ivSpec);
      return Arrays.concatenate(this._iv, this._cx.doFinal(inputText.getBytes("UTF-8")));
    } 
    byte[] decodedValue = Base64.getDecoder().decode(inputText.getBytes());
    int i = 128;
    //GCMParameterSpec params = new GCMParameterSpec(i, inputText.getBytes());
    this._cx.init(2, keySpec, new GCMParameterSpec(i, Arrays.copyOfRange(decodedValue, 0, 16)));
    return this._cx.doFinal(Arrays.copyOfRange(decodedValue, 16, decodedValue.length));
  }
  
  private static String SHA256(String text, int length) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    String resultString;
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(text.getBytes("UTF-8"));
    byte[] digest = md.digest();
    StringBuilder result = new StringBuilder();
    byte b;
    int i;
    byte[] arrayOfByte1;
    for (i = (arrayOfByte1 = digest).length, b = 0; b < i; ) {
      byte b1 = arrayOfByte1[b];
      result.append(String.format("%02x", new Object[] { Byte.valueOf(b1) }));
      b++;
    } 
    if (length > result.toString().length()) {
      resultString = result.toString();
    } else {
      resultString = result.toString().substring(0, length);
    } 
    return resultString;
  }
  
  public String encryptPlainText(String plainText, String key, String iv) throws Exception {
    byte[] bytes = encryptDecrypt(plainText, SHA256(key, 32), EncryptMode.ENCRYPT, iv);
    return Base64.getEncoder().encodeToString(bytes);
  }
  
  public String decryptCipherText(String cipherText, String key, String iv) throws Exception {
    byte[] bytes = encryptDecrypt(cipherText, SHA256(key, 32), EncryptMode.DECRYPT, iv);
    return new String(bytes);
  }
  
  public String encryptPlainTextWithRandomIV(String plainText, String key) throws Exception {
    byte[] bytes = encryptDecrypt(String.valueOf(generateRandomIV16()) + plainText, SHA256(key, 32), EncryptMode.ENCRYPT, generateRandomIV16());
    return Base64.getEncoder().encodeToString(bytes);
  }
  
  public String decryptCipherTextWithRandomIV(String cipherText, String key) throws Exception {
    byte[] bytes = encryptDecrypt(cipherText, SHA256(key, 32), EncryptMode.DECRYPT, generateRandomIV16());
    String out = new String(bytes);
    return out.substring(16, out.length());
  }
  
  public String encryptPlainTextWithRandomIVNew(String plainText, String key) throws Exception {
    byte[] bytes = encryptDecrypt(plainText, key, EncryptMode.ENCRYPT, generateRandomIV16());
    return Base64.getEncoder().encodeToString(bytes);
  }
  
  public String decryptCipherTextWithRandomIVNew(String cipherText, String key) throws Exception {
    byte[] bytes = encryptDecrypt(cipherText, key, EncryptMode.DECRYPT, generateRandomIV16());
    String decryptedString = new String(bytes);
    return decryptedString;
  }
  
  public String generateRandomIV16() {
    SecureRandom ranGen = new SecureRandom();
    byte[] aesKey = new byte[16];
    ranGen.nextBytes(aesKey);
    StringBuilder result = new StringBuilder();
    byte b;
    int i;
    byte[] arrayOfByte1;
    for (i = (arrayOfByte1 = aesKey).length, b = 0; b < i; ) {
      byte b1 = arrayOfByte1[b];
      result.append(String.format("%02x", new Object[] { Byte.valueOf(b1) }));
      b++;
    } 
    if (16 > result.toString().length())
      return result.toString(); 
    return result.toString().substring(0, 16);
  }
  
  
  
  public String generateSharedKey(byte[] privateKeyStr, byte[] publicKeyStr) throws Exception {
	    Security.addProvider((Provider)new BouncyCastleProvider());
	    PrivateKey privateKey = toECPrivateKey(privateKeyStr);
	    PublicKey publicKey = toEcPublicKey(publicKeyStr);
	    KeyAgreement ka1 = null;
	    ka1 = KeyAgreement.getInstance("ECDH");
	    ka1.init(privateKey);
	    ka1.doPhase(publicKey, true);
	    byte[] sharedSecret1 = ka1.generateSecret();
	    return Base64.getEncoder().encodeToString(sharedSecret1);
	  }
	  
	  private static PublicKey toEcPublicKey(byte[] publicKeyByte) throws Exception {
	    String publicKeyStr = byteArrayToHex(publicKeyByte);
	    ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
	    ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(), 
	        params.getN());
	    String pubKeyX = publicKeyStr.substring(0, publicKeyStr.length() / 2);
	    String pubKeyY = publicKeyStr.substring(publicKeyStr.length() / 2);
	    ECPoint ecPoint = new ECPoint(new BigInteger(pubKeyX, 16), new BigInteger(pubKeyY, 16));
	    ECParameterSpec params2 = EC5Util.convertSpec(curveSpec.getCurve(), (org.bouncycastle.jce.spec.ECParameterSpec)params);
	    ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, params2);
	    KeyFactory factory = KeyFactory.getInstance("ECDSA");
	    return factory.generatePublic(keySpec);
	  }
  
  private static String byteArrayToHex(byte[] bytes) {
	    char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	      int v = bytes[j] & 0xFF;
	      hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	      hexChars[j * 2 + 1] = HEX_ARRAY[v & 0xF];
	    } 
	    return new String(hexChars);
	  }
	  
	  private static PrivateKey toECPrivateKey(byte[] privateKeyStr) throws Exception {
	    BigInteger privKey = new BigInteger(privateKeyStr);
	    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
	    ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
	    ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(), 
	        params.getN());
	    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(privKey, (ECParameterSpec)curveSpec);
	    return keyFactory.generatePrivate(keySpec);
	  }
	  
  
}
