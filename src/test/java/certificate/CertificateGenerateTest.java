package certificate;

import com.aobin.certificate.CsrUtils;
import com.aobin.certificate.PemWriter;
import com.aobin.certificate.PrivateKeyUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

public class CertificateGenerateTest {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";



    @Test
    public void test_generateCertificate() throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException, SignatureException, InvalidKeyException, NoSuchProviderException {
    // cert
        String certificateStr = "-----BEGIN CERTIFICATE-----\n" +
                "MIIFWjCCA0ICCQCPI+Mfx1uXgzANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJD\n" +
                "TjETMBEGA1UECAwKbXlwcm92aW5jZTEPMA0GA1UEBwwGbXljaXR5MRcwFQYDVQQK\n" +
                "DA5teW9yZ2FuaXphdGlvbjEQMA4GA1UECwwHbXlncm91cDEPMA0GA1UEAwwGbXlu\n" +
                "YW1lMB4XDTIxMDYxMDA3MTY0NFoXDTIyMDYxMDA3MTY0NFowbzELMAkGA1UEBhMC\n" +
                "Q04xEzARBgNVBAgMCm15cHJvdmluY2UxDzANBgNVBAcMBm15Y2l0eTEXMBUGA1UE\n" +
                "CgwObXlvcmdhbml6YXRpb24xEDAOBgNVBAsMB215Z3JvdXAxDzANBgNVBAMMBm15\n" +
                "bmFtZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANSNcc2OQOXZUMIS\n" +
                "ZG//sAJPSPr5vqJVbCuUPwb01UuIgPVa63YItA6AfQQprmNr565shHHristIa8Vl\n" +
                "vF3YkzAONmNQ4GFp48Ny5/QkPksu+lGbfYcKhrfz4i+38suO4gLayynFwv0hmAb6\n" +
                "v7l2mp8SemSEzDIjoC+7VcmV8qyxUkQn25Uw6/dFfWp8nmtGP9gGGA7LhTlcToMM\n" +
                "16h7dOPTyC0NWCkmmMn73CXKPIrey07yHpLBgp3SsnwCfpZYQryDzns0/v/DeI64\n" +
                "ZA2yTS/F6aOGDdtqI3vW0WJ2vM1NOxBc7bjowU3sZmXBwxgaSZdIM4FEc8bP2Yvq\n" +
                "OJctufbBii56/5Zdkvl1NYK7GaTa6fJuPEscLaSCYZiXS0npnkyBkotDOc/wJIfx\n" +
                "sEJJxxXaMtdTJzAhPnW0kONYdOmbfJwrnkh8xR6bxNHB6WK6tgkJjqIbpe93+twj\n" +
                "NmbU4gpWWtXKnccvlDF6d7cIrbF8JxLI3wChupJFWa9EVWKt2IDGw6lfW+8HQprl\n" +
                "r9+pt1GHzYYy290x1w2rn8WRUlMqU7x8H4tJVKiSL8/1FMV9xCdv2kUdzfNgKeIJ\n" +
                "UWdeZruqE3PVqGtWom+Y1KfTLPtsQlraEE0n+01HqufrvxMB/PrrKZ6/hjGkgCbg\n" +
                "5cDT+uhpnMxvaFNqQKC/z0ljj6mBAgMBAAEwDQYJKoZIhvcNAQEFBQADggIBAA4z\n" +
                "JeBeDevX4oMwHzD1SYowzutmlO5p9PSqHALcwLeLTi13mWmHNmDRTANiFoOqQk14\n" +
                "LXM8lp5zi3AKApG8bRFj5XnfukOXXoRIa7TIG5yIdUokxSYDTlj19biVDdMZdcSa\n" +
                "ad1KKoRIvCIwZQwTDcubS2OHmCyXP5Fi0Nt0odvrFbTHIbvT38cNoCKAbHw/rVfu\n" +
                "Ksbghl3ntrM/GKQR49rbTyZ3DfbgGJrDGPhxGS8s05OFkmznnl8OPv3cnqkseXSR\n" +
                "FIIfT0lXi2DM+0FxCP1lqcFn1f+3bJ6UPDR73MkIhFPKDXFwWOi51B6CZ6R6DQ7e\n" +
                "WYm5IuwIzjaa0P1246WbN3VTeN4Tq7r1fZETTf5N0tK+6rQwwQWCWCXNWAm1/xlj\n" +
                "4ChrOiuapFNzEjTIoGkJkAqXlT1C32Gh3D4KCeD7+pdkQhuVDRJ6nFpUYGPLiNJl\n" +
                "tsYLC8D4TN/jrr3EdMI3BWhfPGAvyUecu0l/P4IfEsbCXU0X725Z6arROFxpPV8x\n" +
                "8UEIyvxOeKfZvH4kf3VKWyUFOvYi7TtQtKfYoEyJZiN6C8Ui71NSmWRBx1IbrLSu\n" +
                "kbVYd4dubPoCJ0ivv6NGdEEAHEcST2jQ8K3aAPvhXZescJIHm/ONAs9Dp7/KRthc\n" +
                "AueAQGhcz0+P6GazwUXyTh+f1rkf5s72eKB2W+ma\n" +
                "-----END CERTIFICATE-----";
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateStr.getBytes()));

        //csr
        String csrStr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBrzCCARgCAQAwbzELMAkGA1UEBhMCQ04xEzARBgNVBAgMCm15cHJvdmluY2Ux\nDzANBgNVBAcMBm15Y2l0eTEXMBUGA1UECgwObXlvcmdhbml6YXRpb24xEDAOBgNV\nBAsMB215Z3JvdXAxDzANBgNVBAMMBm15bmFtZTCBnzANBgkqhkiG9w0BAQEFAAOB\njQAwgYkCgYEAtG5lgcMrvvMz54velM1nZjMMVfwpZITTwYie30ZkvUZSN+SmJ7I5\nQVjLJclTMOFXxJyHwHMGkBMR9A1B9perogR/QRtFVUPVYvQhI7ihmrb90bFrVg34\njqJ6Ontaa+okGfgAXmCSBOnYoc0Rd/eJBFy+ymaxIEXYiNbj5Xbz2DUCAwEAAaAA\nMA0GCSqGSIb3DQEBCwUAA4GBAKV0KA2PHYG743gsrfepmBeoO7giJDWVLkvsYiS4\nfZdTs0Yj4g+1G/hn2hbnoqMqKbX0gBHdAkZ/6Q4fAvbL0fvHfxTijg/ms6b7UWxK\nnvxi+zM9McUXUnPXmU0AcLBCW4yOIQiVZg8Qr3UigTlD+bFaLWbO7IiEGOn88Gck\nURkh\n-----END CERTIFICATE REQUEST-----";
//        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrStr.getBytes());
        PKCS10CertificationRequest csr = CsrUtils.getCsr(csrStr);

        //private key

        //certificate builder
        // random number
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        X500Name rootCertIssuer = new X500Name("CN=root-cert");
        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));


        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));


        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        // Sign the new KeyPair with the root cert Private Key
        String privateKeyStr = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIJKAIBAAKCAgEA1I1xzY5A5dlQwhJkb/+wAk9I+vm+olVsK5Q/BvTVS4iA9Vrr\n" +
                "dgi0DoB9BCmuY2vnrmyEceuKy0hrxWW8XdiTMA42Y1DgYWnjw3Ln9CQ+Sy76UZt9\n" +
                "hwqGt/PiL7fyy47iAtrLKcXC/SGYBvq/uXaanxJ6ZITMMiOgL7tVyZXyrLFSRCfb\n" +
                "lTDr90V9anyea0Y/2AYYDsuFOVxOgwzXqHt049PILQ1YKSaYyfvcJco8it7LTvIe\n" +
                "ksGCndKyfAJ+llhCvIPOezT+/8N4jrhkDbJNL8Xpo4YN22oje9bRYna8zU07EFzt\n" +
                "uOjBTexmZcHDGBpJl0gzgURzxs/Zi+o4ly259sGKLnr/ll2S+XU1grsZpNrp8m48\n" +
                "SxwtpIJhmJdLSemeTIGSi0M5z/Akh/GwQknHFdoy11MnMCE+dbSQ41h06Zt8nCue\n" +
                "SHzFHpvE0cHpYrq2CQmOohul73f63CM2ZtTiClZa1cqdxy+UMXp3twitsXwnEsjf\n" +
                "AKG6kkVZr0RVYq3YgMbDqV9b7wdCmuWv36m3UYfNhjLb3THXDaufxZFSUypTvHwf\n" +
                "i0lUqJIvz/UUxX3EJ2/aRR3N82Ap4glRZ15mu6oTc9Woa1aib5jUp9Ms+2xCWtoQ\n" +
                "TSf7TUeq5+u/EwH8+uspnr+GMaSAJuDlwNP66GmczG9oU2pAoL/PSWOPqYECAwEA\n" +
                "AQKCAgEAta1Eta8+t3f9uDRiVvzUo9TDC4qGsFiVgdZP3RFOcyZ1G8Kf+h7MUIzw\n" +
                "zqsV3PMxb3xf5MOwubroKyyfShPBE1VClbdeYsVQohHIQ3zrJfY8jZ57N/7+UaOL\n" +
                "FMCFLgquEkSTXNwlo5mgSW7wi4Td+tOfe+WqZ7zdwY69b/XUHFngeFMdNDNBrfRe\n" +
                "k7N68TR1g58J1zOMZxAIJ6nFd8Q2kDnIIwIB9gKAnDzD2iU3hHeUjaEUEtqGW4Hp\n" +
                "f2febYF5YYrD5bnRsCmTFWJ0WuSpZwkif9woYgAh3ksqY6AcFttJfd4Ab4m7GHDU\n" +
                "wWtR53sopb9YDsjEsQ2d5CLKRiYWiU1Atfmn792JCCTENU1zvqmH8XFEQxDuwBz2\n" +
                "T0KB0BqRYof2wGebRU0GzQ6gzpIFxWZXVQoEP0HxXy+Jjo6N/3lyhE0SbQmO3heg\n" +
                "U4WHYyXEg19PJmkyUWBYo/J80YBG/kPD88d0VjkR7JUD5/tq/tLviPdBfsm+sS1+\n" +
                "g+hF7pAQ9rtWN+XX/ptn8NszOTZR3Ar0zIL3PMycrkI8aqgBZiYOCld4r4FfitIp\n" +
                "F2KtdxHryj0wgTP7mzcho3JpglJB0FYdfh3jeJajEwdbragBzhi3J85C121eZVdj\n" +
                "JaAmYnzTiamwiCNlXTepblHSFKlOL1R6d0eOt5R/KKAVrWX0VIUCggEBAPeNvCgL\n" +
                "kVLxA76kdt7cicf91mzvr/7Y2UV9OETj0prUZ9pf92nPVKK2It+BjNZYI6HUJA8W\n" +
                "0Vef1it9k7lBs4tx2SnQlLomoWURgcUjYj+YbYcDZiRrmx6oAT+oS6JB//YKCqa/\n" +
                "gip7y0rMXedSLxgy341PMyeqvaxtcWd0pKq0ASk4xgB+oc8fJpynknRCHCM3dXKn\n" +
                "gewNpqy8rpxZhPxkePk+b85fNKwyGkdPOtvcMk3RCis9iNOunnMIizYhnEbxLhdn\n" +
                "lFPishL9CDO3isJwPBK+sTmgb09jxHhBjXZBSwDsIgFqLV4S2u1pxlcezOEf5Yeu\n" +
                "jqx90bzF64Sh0PcCggEBANvN/baTcEoCrVRFxK73t+JtRJ0OhmN37sfHPcFDjnLf\n" +
                "F9haBRa0zNJOAazcVmPoSuRmtbWRmcNZ6XqoezcJgT4MdoP8qda39HnM6cPvrqBO\n" +
                "5jebRZRbMv05OZMyUlNiscOk+va3OFc7Y5ThOp1aF23PUgIeZ/BDhcW+HB0wMXJr\n" +
                "sQemZOh5NN9zJA68kvom75Fux3r7tkIcN3Vd6054qSV00kSSPgQOJM5ZwvOFMk40\n" +
                "19t8JGRi7f+AP04AHq85A4v//dKcMV1R0ZL92z69qPRqmhJjTRjOjxneugha09tq\n" +
                "kRNIZ+h7BmnsjwduQcrVpIIKXmOIXHYJDd8ljER+s0cCggEAK10QkJM2Kak+Vq7I\n" +
                "g9Ft8TJt1TdHRQUHSjzdFnQx+B0s8/vLgyVmVfpBsZUn7oQR+c8HYf1FPmwpQAUH\n" +
                "U3RG1y5iNAjthI4vx1yBtt6z3x/8T6IwykBvM7eKQHRii1G0XIz1wK/bRUXaHoge\n" +
                "Ct9CkKKYtlAhTdmC0Cl7q/uqvJw7d9USGhQUlAuI3/gal3LdKu4UDLl68LaTc765\n" +
                "d3nW6b9P0Zk2TJgwydkc8VDXppuz1B3CAkENLsdvyga9HAZXMbYdtMvYF7mmJ91b\n" +
                "CnQkQlsWqtHsiYOo++cmC0qwVP6q/MZgTo8i00/KObxFmg0zJlxIALR7GYwQqVii\n" +
                "IOGXkQKCAQAwQKlI0lcdODc6v9Isot7wSxJ78/tWjLaTjs6kxaLY3tbKPQDO+kPY\n" +
                "ix1dCEXCyvTd7RpI0LzToMJble7upxyDNZMy6F2UcG+v6WcMB2rrcEajwGdm6Rpp\n" +
                "co2MHcjq20iw7V/Wl2Q76iKzRTpr3qI0DgYvxuMEYJ5WSaS8V58TQkbrqgCO9ETC\n" +
                "JPGudoFBfxiqcYpDGkzpeG5ISqTkZiKjwWCDgyMwGrbDwfrFIOFpP7p/SWJn0zvy\n" +
                "EgJTqj0SNE7uBfV/raA8n0CFp0rhHBuiBGDsVnZPUtEhWb63JNFLYrqUZBnDdHZ0\n" +
                "/GRtuiuhToM9tO8BpKa/lr8/1GtVggbzAoIBADSWlJH03G51RIMv+ZXvS1hZmFcW\n" +
                "bPdEAHzo4ihBhrby2ncxAjxdzyhZpo48+lNWOMQifTiXR61L73Gw03eZehh0+uaV\n" +
                "IfyRhgxqggBJEU7eO2ZM07D1RlIyBwjcMUwHD8keokSswBBIiFiF915GrLWjg4w4\n" +
                "THqgFpUEUTbSqxidO9zHM3S57M879i4PxbKQjYX1saSNDyl920UBZteSxMoylVz/\n" +
                "FOxCl4SA3PZuxSXgOP1J7oIKEoW7WUrRzN9zZuSX1T2xHoHHm4a1PCD2lhkx9wKh\n" +
                "TK0vYgkeH/Eaj7Tyr3Gj+qxMY+QtGRDD61c47RUcwk6hEaIWcdHOfhXYJNc=\n" +
                "-----END RSA PRIVATE KEY-----";
        PrivateKeyUtil privateKeyUtil = new PrivateKeyUtil();
        PrivateKey privateKey = privateKeyUtil.getPrivateKey(privateKeyStr);
        ContentSigner csrContentSigner = csrBuilder.build(privateKey);
        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);
        System.out.println("====== generate certificate=====");
        System.out.println(PemWriter.x509CertificateToPem(issuedCert));
    }
}


















