
// The following code is from http://www.academicpub.org/PaperInfo.aspx?PaperID=14496 .
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;

public class ECCKeyAgreement {
  public static void main(String[] args) throws Exception {
    KeyPairGenerator kpg;
    kpg = KeyPairGenerator.getInstance("EC","SunEC");
    ECGenParameterSpec ecsp;

    ecsp = new ECGenParameterSpec("secp192k1");
    kpg.initialize(ecsp);


    long startu = System.nanoTime();
    KeyPair kpU = kpg.genKeyPair();
    PrivateKey privKeyU = kpU.getPrivate();
    PublicKey pubKeyU = kpU.getPublic();
    long endu = System.nanoTime();
    System.out.println("User U: " + privKeyU.toString());
    System.out.println("User U: " + pubKeyU.toString());
    System.out.println("U takes: "+(startu-endu)+" nanoseconds");

    long startv = System.nanoTime();
    KeyPair kpV = kpg.genKeyPair();
    PrivateKey privKeyV = kpV.getPrivate();
    PublicKey pubKeyV = kpV.getPublic();
    long endv = System.nanoTime();
    System.out.println("User V: " + privKeyV.toString());
    System.out.println("User V: " + pubKeyV.toString());
     System.out.println("V takes: "+(startv-endv)+" nanoseconds");

    KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
    ecdhU.init(privKeyU);
    ecdhU.doPhase(pubKeyV,true);

    KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
    ecdhV.init(privKeyV);
    ecdhV.doPhase(pubKeyU,true);

    System.out.println("Secret computed by U: 0x" + 
                       (new BigInteger(1, ecdhU.generateSecret()).toString(16)).toUpperCase());
    System.out.println("Secret computed by V: 0x" + 
                       (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
  }
}