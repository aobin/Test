package com.aobin.certificate;

import cn.hutool.core.codec.Base64;
import org.bouncycastle.util.io.pem.PemReader;

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
            "-----BEGIN RSA PRIVATE KEY-----\n" +
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
        // avoid exception
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);


        return privKey;
    }


    public static void main(String[] args) throws Exception {
        PrivateKeyUtil privateKeyUtil = new PrivateKeyUtil();
        PrivateKey privateKey = privateKeyUtil.getPrivateKey(PRIVATE_KEY);
        System.out.println(privateKey);
    }

}











