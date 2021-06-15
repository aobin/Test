import com.aobin.CertificateVerify;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

import static junit.framework.TestCase.assertTrue;

public class CertificateVerifyTest {

    @Test
    public void validateCertificateChainSuccess() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//        final File file = new File(CertificateVerifyTest.class.getClassLoader().getResource("server.cer").getFile());
        final File file = new File(CertificateVerifyTest.class.getClassLoader().getResource("server1.cer").getFile());
        final FileInputStream fileInputStream = new FileInputStream(file);
        final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        byte[] encoded = x509Certificate.getPublicKey().getEncoded();
        PublicKey publicKey = getPublicKey();
        try {
            x509Certificate.verify(publicKey);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String format = x509Certificate.getPublicKey().getFormat();
        assertTrue(CertificateVerify.validateCertificateChain(Collections.singletonList(x509Certificate)));
    }


    private PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File f = new File(CertificateVerifyTest.class.getClassLoader().getResource("public-key").getFile());
//        File f = new File(CertificateVerifyTest.class.getClassLoader().getResource("public-key1").getFile());
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

        BASE64Decoder b64 = new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    @Test
    public void test_getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        File file1 = new File(CertificateVerifyTest.class.getClassLoader().getResource("public-key").getFile());
        FileInputStream fis1 = new FileInputStream(file1);
        DataInputStream dis1 = new DataInputStream(fis1);
        byte[] keyBytes1 = new byte[(int) file1.length()];
        dis1.readFully(keyBytes1);
        dis1.close();

        X509EncodedKeySpec spec1 = new X509EncodedKeySpec(keyBytes1);
        KeyFactory kf1 = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) kf1.generatePublic(spec1);
        System.out.println(pubKey);
    }


}
