package certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.Security;

public class CSRTest {


    private Logger LOG = LoggerFactory.getLogger(CSRTest.class);
    private static final String COUNTRY = "2.5.4.6";
    private static final String STATE = "2.5.4.8";
    private static final String LOCALE = "2.5.4.7";
    private static final String ORGANIZATION = "2.5.4.10";
    private static final String ORGANIZATION_UNIT = "2.5.4.11";
    private static final String COMMON_NAME = "2.5.4.3";//CN域名
    private static final String EMAIL = "2.5.4.9";


    @Test
    public void testReadCertificateSigningRequest() {
        String csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIBrzCCARgCAQAwbzELMAkGA1UEBhMCQ04xEzARBgNVBAgMCm15cHJvdmluY2Ux\n" +
                "DzANBgNVBAcMBm15Y2l0eTEXMBUGA1UECgwObXlvcmdhbml6YXRpb24xEDAOBgNV\n" +
                "BAsMB215Z3JvdXAxDzANBgNVBAMMBm15bmFtZTCBnzANBgkqhkiG9w0BAQEFAAOB\n" +
                "jQAwgYkCgYEAlaNwDf8s2iTUv3LM4Y+qSI7nqXihr/ggHMAfyNhLIX3YSiF7NTru\n" +
                "pxNe35ez8KCJi3hbSnKhWklZCDE1mDIvqjqAS68l7dcSepCkLvQlrkv4MkwUPc3K\n" +
                "ndzLqQZ6dRa8BCmqAUzdRVd6pEo2C6mUZ8jEwcMtMQPLK5KbsjBU+wsCAwEAAaAA\n" +
                "MA0GCSqGSIb3DQEBCwUAA4GBAGim34sUG41gn1QLSk65Hn0T5nbmGTnSF+elIIAq\n" +
                "a5mUSEnkMzs30zRdDJ+X2jUjksIk2QTjVWiHMLiM/5GVe/XOffrcz0Jg7ucOZ7bH\n" +
                "FhuY9irCmMEpAXVMIUeuWGL1V8UEzZG1KeAjCin0ByehIuaFwWJF/rLejXKeyibl\n" +
                "q7Q8\n" +
                "-----END CERTIFICATE REQUEST-----";

        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrPEM);

        X500Name x500Name = csr.getSubject();
        System.out.println("x500Name is: " + x500Name + "\n");

        // country is 2.5.4.6
        System.out.println("COUNTRY: " + getX500Field(COUNTRY, x500Name));
        // state is 2.5.4.8
        System.out.println("STATE: " + getX500Field(STATE, x500Name));
        // locale is 2.5.4.7
        System.out.println("LOCALE: " + getX500Field(LOCALE, x500Name));

        // locale is 2.5.4.3
        System.out.println("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name));

        //organization 2.5.4.10
        System.out.println("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name));
        //organization unit 2.5.4.11
        System.out.println("ORGANIZATION unit: " + getX500Field(ORGANIZATION_UNIT, x500Name));

        System.out.println("EMAIL: " + getX500Field(EMAIL, x500Name));



    }

    private String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));
        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }

        return retVal;
    }

    private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            LOG.error("UnsupportedEncodingException, convertPemToPublicKey", ex);
        }

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            System.out.println("PemParser returned: " + parsedObj);

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

            }
        } catch (IOException ex) {
            LOG.error("IOException, convertPemToPublicKey", ex);
        }

        return csr;
    }

    private String toPEM(Object key) {
        StringWriter sw = new StringWriter();
        PEMWriter pem = new PEMWriter(sw);
        try {
            pem.writeObject(key);
            pem.close();
        } catch (IOException e) {
            System.out.printf("IOException: %s%n", e);
        }
        return sw.toString();
    }

}
