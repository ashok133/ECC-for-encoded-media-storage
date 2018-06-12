import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

public class RSA {

    private static String bytes2String(byte[] bytes) {
    StringBuilder string = new StringBuilder();
    for (byte b : bytes) {
        String hexString = Integer.toHexString(0x00FF & b);
        string.append(hexString.length() == 1 ? "0" + hexString : hexString);
    }
    return string.toString();
}
    
  public static void main(String[] args) throws Exception {
    /*Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");

    keyGen.initialize(512, new SecureRandom());

    KeyPair keyPair = keyGen.generateKeyPair();
    Signature signature = Signature.getInstance("SHA1withRSA", "BC");

    signature.initSign(keyPair.getPrivate(), new SecureRandom());

    byte[] message = "abc".getBytes();
    signature.update(message);

    byte[] sigBytes = signature.sign();
    signature.initVerify(keyPair.getPublic());
    signature.update(message);
    System.out.println(signature.verify(sigBytes));*/
    // Generate new key
KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
PrivateKey privateKey = keyPair.getPrivate();
String plaintext = "This is the message being signed";

// Compute signature
Signature instance = Signature.getInstance("SHA1withRSA");
instance.initSign(privateKey);
instance.update((plaintext).getBytes());
byte[] signature = instance.sign();

// Compute digest
MessageDigest sha1 = MessageDigest.getInstance("SHA1");
byte[] digest = sha1.digest((plaintext).getBytes());

// Encrypt digest
Cipher cipher = Cipher.getInstance("RSA");
cipher.init(Cipher.ENCRYPT_MODE, privateKey);
byte[] cipherText = cipher.doFinal(digest);

// Display results
System.out.println("Input data: " + plaintext);
System.out.println("Digest: " + bytes2String(digest));
System.out.println("Cipher text: " + bytes2String(cipherText));
System.out.println("Signature: " + bytes2String(signature));
  }
}