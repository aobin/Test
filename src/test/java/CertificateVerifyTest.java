import com.aobin.CertificateVerify;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.io.*;
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
//        final File file = new File(CertificateVerifyTest.class.getClassLoader().getResource("server1.cer").getFile());
        String certificateStr = "-----BEGIN CERTIFICATE-----\nMIID1jCCAb4CCQDO0oD3WvNjDDANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJD\nTjETMBEGA1UECAwKbXlwcm92aW5jZTEPMA0GA1UEBwwGbXljaXR5MRcwFQYDVQQK\nDA5teW9yZ2FuaXphdGlvbjEQMA4GA1UECwwHbXlncm91cDEPMA0GA1UEAwwGbXlu\nYW1lMB4XDTIxMDYxNjEzMTk0M1oXDTIxMDYxNzEzMTk0M1owbzELMAkGA1UEBhMC\nQ04xEzARBgNVBAgMCm15cHJvdmluY2UxDzANBgNVBAcMBm15Y2l0eTEXMBUGA1UE\nCgwObXlvcmdhbml6YXRpb24xEDAOBgNVBAsMB215Z3JvdXAxDzANBgNVBAMMBm15\nbmFtZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtG5lgcMrvvMz54velM1n\nZjMMVfwpZITTwYie30ZkvUZSN+SmJ7I5QVjLJclTMOFXxJyHwHMGkBMR9A1B9per\nogR/QRtFVUPVYvQhI7ihmrb90bFrVg34jqJ6Ontaa+okGfgAXmCSBOnYoc0Rd/eJ\nBFy+ymaxIEXYiNbj5Xbz2DUCAwEAATANBgkqhkiG9w0BAQUFAAOCAgEAPkuUfndW\nWwDgndhCZ9ctCHUoek/yu0EnLbAIFbbBMboZvzUTRtcyUePQDFNO6Hjt4SjtR5M4\nq3xG8FTu8+cAR1vTe30qTRuLWx2N/JpiNQk+FqkvZNVLXMKa3obIYPgkKDusmsuf\nV5pl1RsvMZ3BC9fWJtV/B8MHcS+n4LpXp3tbMoig5CSM1XddVB+RE7JkMhrZxkFk\neJnzHlhnMnDHuPcfvYgcWNxy8+rebzlga/GBjO2RI9HAZaZvKMp93rtr95FTRpgg\niYUrsz3hqXrKSfx1idAAgORItyvqXcaX7APhOh8aiVKL0OrjiriXv4PHi6ot33I/\nRAvORAYhraxPa4f92VBgND0T0Fd15iLspvj9YjfvwrjVQFBu1l0bIFvJCvt45YLx\nMuLq+rKZrEyNkQbazupzGxk1DN6Ay5Oueo/jh+95ct75EeFDVrNoW81PFwIc7Kwj\nXJ472AVjwpu0qljlrKro17nhECiAy/xg7sDibXidBaTaQkJDJGbRdUYMxV54gdo+\nAIw3whP/XZObptVdlE+5o138QRRSldSSpoRZKtutI03R81TVWjEESyqwVU0UixUR\ndKB+yVcCD4Bfiwbd/GFCavpO6oUauU96hjw6JaXdGmC7o+dqjgI9Zlgpria/AyVB\nl9VntVPmd0RMjRHLOFcfqql5ZV9DOw31v/4=\n-----END CERTIFICATE-----\n";
//        final FileInputStream fileInputStream = new FileInputStream(file);
//        final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

        final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateStr.getBytes()));
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
