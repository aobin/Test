package com.aobin.certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

public class PemWriter {

    public static String x509CertificateToPem(final X509Certificate cert) throws IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public static String convertCertToPem(final PKCS10CertificationRequest certRequest) throws IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certRequest);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }
}
