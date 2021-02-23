import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.*;
import org.bouncycastle.util.encoders.Hex;
import sun.misc.BASE64Decoder;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Hashtable;

public class ED25519Test {

    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(keyBytes);
        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);
        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);
        return keyOut;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(keyBytes);
        EdDSAPrivateKey keyIn = new EdDSAPrivateKey(encoded);
        // Encode
        EdDSAPrivateKeySpec decoded = new EdDSAPrivateKeySpec(
                keyIn.getSeed(),
                keyIn.getH(),
                keyIn.geta(),
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPrivateKey keyOut = new EdDSAPrivateKey(decoded);
        return keyOut;
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        return keyPairGenerator.generateKeyPair();
    }


    public static byte[] ed25519Sign(byte[] msg, PrivateKey privateKey) throws InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
        EdDSAEngine edDSAEngine = new EdDSAEngine();
        edDSAEngine.initSign(privateKey);
        edDSAEngine.setParameter(EdDSAEngine.ONE_SHOT_MODE);
        edDSAEngine.update(msg);
        return edDSAEngine.sign();
    }

    public static boolean ed25519VerifySign(byte[] msg, byte[] sign, PublicKey publicKey) throws InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
        EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("ED_25519");
        EdDSAEngine edDSAEngine = new EdDSAEngine();
        edDSAEngine.initVerify(publicKey);
        edDSAEngine.setParameter(EdDSAEngine.ONE_SHOT_MODE);
        edDSAEngine.update(msg);
        Boolean isSuccess = edDSAEngine.verify(sign);
        return isSuccess;
    }

    public static void main(String[] args) throws Exception {

        // 原数据
        String dataStr = "6E1B2C99438AE66A356102CEBF5577E7";
        byte[] data = Hex.decode(dataStr);

        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        System.out.println("Public Key: " + keyPair.getPublic().toString());
        System.out.println("Private Key: " + keyPair.getPrivate().toString());

        // 签名
        byte[] sign = ed25519Sign(data, keyPair.getPrivate());
        System.out.println("sign: " + Hex.toHexString(sign));

        // 验签
        Boolean res = ed25519VerifySign(data, sign, keyPair.getPublic());
        System.out.println("result: " + res);

        // 外部公钥验签
        PublicKey publicKey = getPublicKey("MCowBQYDK2VwAyEAzQBte5CcSmqTy46Y3e6l0LRuNzwl54wFkpci81cWDpA=");
        String signStr = "5acfe33ac9770a80870dcdd05a7da588aad6dc87aed4c401748a9983f5fda4f7a94d455355c8fdfaccae3885d45018013de774a0a54d0efc7f5b19b9f163e00c";
        byte[] signBytes = Hex.decode(signStr);
        Boolean isSuccess = ed25519VerifySign(data, signBytes, publicKey);
        System.out.println("result: " + isSuccess);
    }
}
