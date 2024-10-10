/*
Copyright (c) 2016 NCC Group Security Services, Inc. All rights reserved.
Licensed under Dual BSD/GPLv2 per the repo LICENSE file.
*/

import org.apache.commons.codec.binary.Base64;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class YoloCertKey {

  public X509Certificate cert;
  public KeyPair keypair;
  public PrivateKey key;

  public YoloCertKey(X509Certificate _cert, PrivateKey _key) {
    cert = _cert;
    key = _key;
    keypair = new KeyPair(cert.getPublicKey(), key);
  }

  public static YoloCertKey newInstance(String commonName, String organizationUnit,
                                        String organizationName, String localityName,
                                        String stateName, String country) {

    try {
      CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
      keypair.generate(2048);

      X500Name x500Name = new X500Name(commonName, organizationUnit, organizationName, localityName, stateName, country);

      return new YoloCertKey(
        keypair.getSelfCertificate(x500Name, new Date(), (long) 100 * 24 * 60 * 60),
        keypair.getPrivateKey()
      );
    } catch (Throwable t) {
      t.printStackTrace();
      return null;
    }
  }

  public static YoloCertKey newInstance() {
    return newInstance("Honest Jeff's CA Emporium", "Don't run Wireshark as root", "NCC", "NYC", "NY", "US");
  }

  public static YoloCertKey newInstance(String commonName) {
    return newInstance(commonName, "Don't run Wireshark as root", "NCC", "NYC", "NY", "US");
  }

  public static YoloCertKey newInstance(String commonName, String organizationUnit) {
    return newInstance(commonName, organizationUnit, "NCC", "NYC", "NY", "US");
  }


  public String getCert() {
    try {
      StringBuilder ret = new StringBuilder();

      Base64 encoder = new Base64(64);
      String header = "-----BEGIN CERTIFICATE-----\n";
      String footer = "-----END CERTIFICATE-----\n";

      ret.append(header);
      ret.append(new String(encoder.encode(cert.getEncoded())));
      ret.append(footer);

      return ret.toString();
    } catch (Throwable t) {
      t.printStackTrace();
      return null;
    }
  }

  public String getKey() {
    try {
      StringBuilder ret = new StringBuilder();

      Base64 encoder = new Base64(64);
      String header = "-----BEGIN PRIVATE KEY-----\n";
      String footer = "-----END PRIVATE KEY-----\n";

      ret.append(header);
      ret.append(new String(encoder.encode(key.getEncoded())));
      ret.append(footer);

      return ret.toString();
    } catch (Throwable t) {
      t.printStackTrace();
      return null;
    }
  }

}
