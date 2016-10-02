/* Copyright Rene Mayrhofer, 2006-03-19
 * 
 * This file may be copied under the terms of the GNU GPL version 2.
 */

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.X509CertificateObject;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Calendar;
import java.util.Date;

/** This class uses the Bouncycastle lightweight API to generate X.509 certificates programmatically.
 * It assumes a CA certificate and its private key to be available and can sign the new certificate with
 * this CA. Some of the code for this class was taken from 
 * org.bouncycastle.x509.X509V3CertificateGenerator, but adapted to work with the lightweight API instead of
 * JCE (which is usually not available on MIDP2.0). 
 *
 * @author Rene Mayrhofer
 */
public class X509CertificateGenerator {
  /** Our log4j logger. */

  /** This holds the certificate of the CA used to sign the new certificate. The object is created in the constructor. */
  private X509Certificate caCert;
  /** This holds the private key of the CA used to sign the new certificate. The object is created in the constructor. */
  private RSAPrivateCrtKeyParameters caPrivateKey;

  /*
  public X509CertificateGenerator(String caFile, String caPassword, String caAlias)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {

    System.out.println("Loading CA certificate and private key from file '" + caFile + "', using alias '" + caAlias + "' with "
      + "JCE API");
    KeyStore caKs = KeyStore.getInstance("PKCS12");
    caKs.load(new FileInputStream(new File(caFile)), caPassword.toCharArray());

    // load the key entry from the keystore
    Key key = caKs.getKey(caAlias, caPassword.toCharArray());
    if (key == null) {
      throw new RuntimeException("Got null key from keystore!");
    }
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
    caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(),
      privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());
    // and get the certificate
    caCert = (X509Certificate) caKs.getCertificate(caAlias);
    if (caCert == null) {
      throw new RuntimeException("Got null cert from keystore!");
    }
    System.out.println("Successfully loaded CA key and certificate. CA DN is '" + caCert.getSubjectDN().getName() + "'");
    caCert.verify(caCert.getPublicKey());
    System.out.println("Successfully verified CA certificate with its own public key.");
  }
*/

  private static class Holder {
    X509Certificate cert;
    RSAPrivateCrtKey key;
  }

  private static X509CertificateGenerator.Holder getHolder(String caFile, String caPassword, String caAlias)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {

    System.out.println("Loading CA certificate and private key from file '" + caFile + "', using alias '" + caAlias + "' with "
      + "JCE API");
    KeyStore caKs = KeyStore.getInstance("PKCS12");
    caKs.load(new FileInputStream(new File(caFile)), caPassword.toCharArray());

    // load the key entry from the keystore
    Key key = caKs.getKey(caAlias, caPassword.toCharArray());
    if (key == null) {
      throw new RuntimeException("Got null key from keystore!");
    }

    X509CertificateGenerator.Holder h = new X509CertificateGenerator.Holder();
    h.cert = (X509Certificate) caKs.getCertificate(caAlias);
    h.key = (RSAPrivateCrtKey)key;
    return h;
  }

  public X509CertificateGenerator(String caFile, String caPassword, String caAlias)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this(getHolder(caFile, caPassword, caAlias));
  }

  private X509CertificateGenerator(X509CertificateGenerator.Holder holder)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this(holder.cert, holder.key);
  }

  public X509CertificateGenerator(X509Certificate _caCert, RSAPrivateCrtKey privKey)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {

    if (_caCert == null) {
      throw new RuntimeException("Got null cert from keystore!");
    }
    caCert = _caCert;

    caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(),
      privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());

    System.out.println("Successfully loaded CA key and certificate. CA DN is '" + caCert.getSubjectDN().getName() + "'");
    System.out.println("caCert.getPublicKey(): " + caCert.getPublicKey());
    caCert.verify(caCert.getPublicKey());
    System.out.println("Successfully verified CA certificate with its own public key.");
  }


  public YoloCertKey createCertificate(String dn, int validityDays) throws
    IOException, InvalidKeyException, SecurityException, SignatureException, NoSuchAlgorithmException, DataLengthException, CryptoException, KeyStoreException, NoSuchProviderException, CertificateException, InvalidKeySpecException {
    System.out.println("Generating certificate for distinguished subject name '" +
      dn + "', valid for " + validityDays + " days");
    SecureRandom sr = new SecureRandom();

    PublicKey pubKey;
    PrivateKey privKey;

    System.out.println("Creating RSA keypair");
    // generate the keypair for the new certificate
    // this is the JSSE way of key generation
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048, sr);
    KeyPair keypair = keyGen.generateKeyPair();
    privKey = keypair.getPrivate();
    pubKey = keypair.getPublic();

    Calendar expiry = Calendar.getInstance();
    expiry.add(Calendar.DAY_OF_YEAR, validityDays);

    X500Name/*X509Name*/ x509Name = new X500Name/*X509Name*/("CN=" + dn);

    V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
    certGen.setSerialNumber(new ASN1Integer/*DERInteger*/(BigInteger.valueOf(System.currentTimeMillis())));
    //certGen.setIssuer(PrincipalUtil.getSubjectX509Principal(caCert));
    certGen.setIssuer(X500Name.getInstance(caCert.getIssuerX500Principal().getEncoded()));
    certGen.setSubject(x509Name);
    ASN1ObjectIdentifier/*DERObjectIdentifier*/ sigOID = PKCSObjectIdentifiers.sha256WithRSAEncryption;//X509Util.getAlgorithmOID("SHA1WithRSAEncryption");
    AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE/*new DERNull()*/);
    certGen.setSignature(sigAlgId);
    //certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
    //  new ByteArrayInputStream(pubKey.getEncoded())).readObject()));
    certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(
      ASN1Sequence.getInstance(pubKey.getEncoded()))
    );
    certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
    certGen.setEndDate(new Time(expiry.getTime()));

    System.out.println("Certificate structure generated, creating SHA1 digest");
    // attention: hard coded to be SHA1+RSA!
    SHA1Digest digester = new SHA1Digest();
    AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSAEngine());
    TBSCertificate/*Structure*/ tbsCert = certGen.generateTBSCertificate();

    ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
    DEROutputStream         dOut = new DEROutputStream(bOut);
    dOut.writeObject(tbsCert);

    // and now sign
    byte[] signature;
    // or the JCE way
    PrivateKey caPrivKey = KeyFactory.getInstance("RSA").generatePrivate(
      new RSAPrivateCrtKeySpec(caPrivateKey.getModulus(), caPrivateKey.getPublicExponent(),
        caPrivateKey.getExponent(), caPrivateKey.getP(), caPrivateKey.getQ(),
        caPrivateKey.getDP(), caPrivateKey.getDQ(), caPrivateKey.getQInv()));

    Signature sig = Signature.getInstance(sigOID.getId());
    sig.initSign(caPrivKey, sr);
    sig.update(bOut.toByteArray());
    signature = sig.sign();
    System.out.println("SHA1/RSA signature of digest is '" + new String(Hex.encodeHex(signature)) + "'");

    // and finally construct the certificate structure
    ASN1EncodableVector  v = new ASN1EncodableVector();

    v.add(tbsCert);
    v.add(sigAlgId);
    v.add(new DERBitString(signature));

    //X509CertificateObject clientCert = new X509CertificateObject(new X509CertificateStructure(new DERSequence(v)));
    X509CertificateObject clientCert = new X509CertificateObject(Certificate.getInstance(new DERSequence(v)));

    System.out.println("Verifying certificate for correct signature with CA public key");
    clientCert.verify(caCert.getPublicKey());

    // and export as PKCS12 formatted file along with the private key and the CA certificate
    System.out.println("Exporting certificate in PKCS12 format");

    return new YoloCertKey(clientCert, privKey);
  }

}