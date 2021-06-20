package com.aobin.certificate;

import java.security.cert.X509Certificate;
import java.util.List;

public class CertificateVerify {

    public static boolean validateCertificateChain(final List<X509Certificate> certificates) {
        for (int i = 0; i < certificates.size(); i++) {
            try {
                if (i == certificates.size() - 1) {
                    if (isSelfSigned(certificates.get(i))) {
                        certificates.get(i).verify(certificates.get(i).getPublicKey());
                    }
                } else {
                    certificates.get(i).verify(certificates.get(i + 1).getPublicKey());
                }
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Determine if the given certificate is self signed.
     *
     * @param certificate Certificate to be verified as self-signed against its own public key.
     *
     * @return <code>true</code> if the certificate is self signed
     *         <code>false</code> otherwise, in the case of any exception.
     */
    private static boolean isSelfSigned(final X509Certificate certificate) {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }




}
