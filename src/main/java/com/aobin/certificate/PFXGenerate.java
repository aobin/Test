package com.aobin.certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PFXGenerate {

    /**
     * 算法提供者 Bouncy Castle
     */
    private static final Provider BC = new BouncyCastleProvider();

    /**
     * 生成 RSA PFX 证书
     *
     * @param key P8 格式 Base64 私钥
     * @param cert Base64 证书
     * @param password 保护私钥的密码
     * @return PFX Base64 文件数据
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     */
    public static String generateRSAPFX(String key, String cert, String password)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchProviderException, KeyStoreException {

        try (
                ByteArrayInputStream certInput = new ByteArrayInputStream(Base64.getDecoder().decode(cert));
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ) {

            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BC);
            Certificate certificate = certificateFactory.generateCertificate(certInput);

            KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);
            keyStore.load(null, null);
            keyStore.setKeyEntry("zjca", privateKey, password.toCharArray(), new Certificate[]{ certificate });
            keyStore.store(outputStream, password.toCharArray());
            outputStream.flush();

            byte[] pfx = outputStream.toByteArray();

            return Base64.getEncoder().encodeToString(pfx);
        }
    }

    public static void main(String[] args) throws IOException {
        // Base64 公钥证书
        String cert = Files.readAllLines(Paths.get("E:\\Temp\\cert.txt")).get(0);
        // 证书私钥
        String key = Files.readAllLines(Paths.get("E:\\Temp\\private_key.txt")).get(0);
        // 保护私钥的密码
        String password = "123";

        try {
            System.out.println(generateRSAPFX(key, cert, password));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | NoSuchProviderException | KeyStoreException e) {
            e.printStackTrace();
        }
    }
}
