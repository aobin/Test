package com.aobin.certificate;

import cn.hutool.core.codec.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyUtil {

    private final static String PRIVATE_KEY =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM7t8Ub1DP+B91NJ\n"
                    + "nC45zqIvd1QXkQ5Ac1EJl8mUglWFzUyFbhjSuF4mEjrcecwERfRummASbLoyeMXl\n"
                    + "eiPg7jvSaz2szpuV+afoUo9c1T+ORNUzq31NvM7IW6+4KhtttwbMq4wbbPpBfVXA\n"
                    + "IAhvnLnCp/VyY/npkkjAid4c7RoVAgMBAAECgYBcCuy6kj+g20+G5YQp756g95oN\n"
                    + "dpoYC8T/c9PnXz6GCgkik2tAcWJ+xlJviihG/lObgSL7vtZMEC02YXdtxBxTBNmd\n"
                    + "upkruOkL0ElIu4S8CUwD6It8oNnHFGcIhwXUbdpSCr1cx62A0jDcMVgneQ8vv6vB\n"
                    + "/YKlj2dD2SBq3aaCYQJBAOvc5NDyfrdMYYTY+jJBaj82JLtQ/6K1vFIwdxM0siRF\n"
                    + "UYqSRA7G8A4ga+GobTewgeN6URFwWKvWY8EGb3HTwFkCQQDgmKtjjJlX3BotgnGD\n"
                    + "gdxVgvfYG39BL2GnotSwUbjjce/yZBtrbcClfqrrOWWw7lPcX1d0v8o3hJfLF5dT\n"
                    + "6NAdAkA8qAQYUCSSUwxJM9u0DOqb8vqjSYNUftQ9dsVIpSai+UitEEx8WGDn4SKd\n"
                    + "V8kupy/gJlau22uSVYI148fJSCGRAkBz+GEHFiJX657YwPI8JWHQBcBUJl6fGggi\n"
                    + "t0F7ibceOkbbsjU2U4WV7sHyk8Cei3Fh6RkPf7i60gxPIe9RtHVBAkAnPQD+BmND\n"
                    + "By8q5f0Kwtxgo2+YkxGDP5bxDV6P1vd2C7U5/XxaN53Kc0G8zu9UlcwhZcQ5BljH\n"
                    + "N24cUWZOo+60\n"
                    + "-----END PRIVATE KEY-----";


    public PrivateKey getPrivateKey(String privateKeyStr) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(privateKeyStr));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END RSA PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        // Base64 decode the result

        byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }


    public static void main(String[] args) throws Exception {

    }

}
