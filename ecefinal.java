
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.util.encoders.Hex;

public class ecefinal {
 KeyPairGenerator kpg;
 EllipticCurve curve;
 ECParameterSpec ecSpec;
 KeyPair aKeyPair;
 KeyAgreement aKeyAgree;
 KeyPair bKeyPair;
 KeyAgreement bKeyAgree;
 KeyFactory keyFac;
 
 public ecefinal()
 {
  try{
   this.kpg = KeyPairGenerator.getInstance("ECDH", "BC");     
   this.curve = new EllipticCurve(
     new ECFieldFp(
      new BigInteger(
       "883423532389192164791648750360308885314476597252960362792450860609699839")), // q
     new BigInteger(
      "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
      16), // a
     new BigInteger(
      "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
      16) //b
    );
   
   this.ecSpec = new ECParameterSpec(
     curve,
     ECPointUtil.decodePoint(
      curve,
      Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
     new BigInteger(
      "883423532389192164791648750360308884807550341691627752275345424702807307"), // n
      1); // h
   
   this.kpg.initialize(ecSpec, new SecureRandom());
   GenerateKeyPair();
      
  }catch(Exception err){
   log(err.toString());
  }
 }
 
 public void GenerateKeyPair(){
  try
  {
   //
   // a side
   //
   aKeyPair = this.kpg.generateKeyPair();
   aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
   aKeyAgree.init(aKeyPair.getPrivate());

   //
   // b side
   //   
   bKeyPair = this.kpg.generateKeyPair();
   bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
   bKeyAgree.init(bKeyPair.getPrivate());
   
   aKeyAgree.doPhase(bKeyPair.getPublic(), true);
   bKeyAgree.doPhase(aKeyPair.getPublic(), true);
  }
  catch(Exception err){
   log(err.toString());
  }
 }
 
 public void log(String data){
  System.out.println(data);
 }
 
 public String Encrypt(byte[] data){
  try
  {
   
   log(Base64.encodeBase64String(bKeyAgree.generateSecret()));
   log(Base64.encodeBase64String(aKeyAgree.generateSecret()));

   BigInteger k1 = new BigInteger(aKeyAgree.generateSecret());
   BigInteger k2 = new BigInteger(bKeyAgree.generateSecret());
   if (!k1.equals(k2)) {
    log(" 2-way test failed");
   }
   
   byte[] aBys = aKeyAgree.generateSecret(); 
   KeySpec aKeySpec = new DESKeySpec(aBys);
   SecretKeyFactory aFactory = SecretKeyFactory.getInstance("DES");
   Key aSecretKey = aFactory.generateSecret(aKeySpec);

   Cipher aCipher = Cipher.getInstance(aSecretKey.getAlgorithm());   
   aCipher.init(Cipher.ENCRYPT_MODE, aSecretKey);  
   byte[] encText = aCipher.doFinal(data);
   
   log(Base64.encodeBase64String(encText));
   return Base64.encodeBase64String(encText);
  }
  catch(Exception err){
   log(err.toString());
   return "";
  }
 }
 
 public String Decrypt(byte[] data){
  try
  {
   byte[] bBys = bKeyAgree.generateSecret(); 
   KeySpec bKeySpec = new DESKeySpec(bBys);
   SecretKeyFactory bFactory = SecretKeyFactory.getInstance("DES");
   Key bSecretKey = bFactory.generateSecret(bKeySpec);

   Cipher bCipher = Cipher.getInstance(bSecretKey.getAlgorithm());   
   bCipher.init(Cipher.DECRYPT_MODE, bSecretKey);   

   byte[] decText =  bCipher.doFinal(Base64.decodeBase64(data)); 
   String text = new String(decText);
   log(text);
   return text;   
  }
  catch(Exception err){
   log(err.toString());
   return "";
  }
 }
 
 public void pubKeyEncodingTest(){
  try
  {
   //
   // public key encoding test
   //
   byte[] pubEnc = aKeyPair.getPublic().getEncoded();
   keyFac = KeyFactory.getInstance("ECDH", "BC");
   X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
   ECPublicKey pubKey = (ECPublicKey) keyFac.generatePublic(pubX509);

   if (!pubKey.getW().equals(((ECPublicKey) aKeyPair.getPublic()).getW())) {
     System.out.println(" expected " + pubKey.getW().getAffineX()
      + " got "
      + ((ECPublicKey) aKeyPair.getPublic()).getW().getAffineX());
     System.out.println(" expected " + pubKey.getW().getAffineY()
      + " got "
      + ((ECPublicKey) aKeyPair.getPublic()).getW().getAffineY());
     log("ECDH" + " public key encoding (W test) failed");
   }

   if (!pubKey.getParams().getGenerator()
    .equals(
     ((ECPublicKey) aKeyPair.getPublic()).getParams()
      .getGenerator())) {
     log("ECDH" + " public key encoding (G test) failed");
   }
  }
  catch(Exception err){
   log(err.toString());
  }
 }
 
 public void PrivateKeyEncodingTest(){
  try
  {
   //
   // private key encoding test
   //
   byte[] privEnc = aKeyPair.getPrivate().getEncoded();
   PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
   ECPrivateKey privKey = (ECPrivateKey) keyFac.generatePrivate(privPKCS8);

   if (!privKey.getS().equals(
    ((ECPrivateKey) aKeyPair.getPrivate()).getS())) {
     log("ECDH" + " private key encoding (S test) failed");
   }

   if (!privKey.getParams().getGenerator().equals(
    ((ECPrivateKey) aKeyPair.getPrivate()).getParams()
     .getGenerator())) {
     log("ECDH" + " private key encoding (G test) failed");
   }
  }
  catch(Exception err){
   
  }
 }
}