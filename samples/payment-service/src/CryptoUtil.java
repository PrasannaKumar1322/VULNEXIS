import java.security.*;
import javax.crypto.*;

public class CryptoUtil {
    public static KeyPair rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    public static Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding"); // Triple DES
    }

    public static KeyAgreement dh() throws Exception {
        return KeyAgreement.getInstance("DH");
    }

    public static Cipher modern() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding"); // AES-256 keys only
    }
}
