//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.kubernetes.artifacts.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tremolosecurity.kubernetes.artifacts.obj.CertificateData;
import com.tremolosecurity.kubernetes.artifacts.obj.X509Data;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;

/**
 * Static utility class meant for being called from within javascript
 */
public class CertUtils {
    static SecureRandom secRandom = new SecureRandom();

    /**
     * Generates an AES-256 SecretKey
     * 
     * @return
     * @throws Exception
     */
    public static void createKey(KeyStore ks, String alias, String ksPassword) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, secRandom);
        SecretKey sk = kg.generateKey();
        ks.setKeyEntry(alias, sk, ksPassword.toCharArray(), null);
    }

    /**
     * Exports a key to a base64 encoded string
     */
    public static String exportKey(KeyStore ks, String alias, String ksPassword) throws Exception {
        SecretKey key = (SecretKey) ks.getKey(alias, ksPassword.toCharArray());
        return java.util.Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Stores the key in the keystore
     */
    public static void storeKey(KeyStore ks, String alias, String ksPassword, String encodedKey)
            throws KeyStoreException {
        byte[] rawKey = java.util.Base64.getDecoder().decode(encodedKey);
        SecretKey sc = new SecretKeySpec(rawKey, "AES");
        ks.setKeyEntry(alias, sc, ksPassword.toCharArray(), null);
    }

    /**
     * Create an X509Data object from a JSON version from JavaScript
     * 
     * @param fromjs
     * @return
     * @throws Exception
     */
    public static X509Data createCertificate(Map fromjs) throws Exception {
        CertificateData data = new ObjectMapper().convertValue(fromjs, CertificateData.class);

        return createCertificate(data);
    }

    /**
     * Create a certificate and keypair based on a certificate data object
     * 
     * @param certData
     * @return
     * @throws Exception
     */
    public static X509Data createCertificate(CertificateData certData) throws Exception {
        String keyAlg = "RSA";

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg);
        kpg.initialize(certData.getSize(), secRandom);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dnName = new X500Name("CN=" + certData.getServerName() + ", OU=" + certData.getOu() + ", O="
        + certData.getO() + ", L=" + certData.getL() + ", ST=" + certData.getSt() + ", C=" + certData.getC());

        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());

        ContentSigner contentSigner = new JcaContentSignerBuilder(certData.getSigAlg()).build(kp.getPrivate());

        Instant startDate = Instant.ofEpochMilli(certData.getNotBefore().getTime());
        Instant endDate = Instant.ofEpochMilli(certData.getNotAfter().getTime());


        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        dnName, certSerialNumber, Date.from(startDate), Date.from(endDate), dnName,
        kp.getPublic());

        if (certData.isCaCert()) {
            //certBuilder.addExtension(Extension.create(Extension.basicConstraints, true, new BasicConstraints(true)));
            certBuilder.addExtension(Extension.create(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)));
            certBuilder.addExtension(Extension.create(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)));
        }

        GeneralName[] names = new GeneralName[certData.getSubjectAlternativeNames().size() + 1];
        names[0] = new GeneralName(GeneralName.dNSName, certData.getServerName());
        for (int i = 0; i < certData.getSubjectAlternativeNames().size(); i++) {
            names[i + 1] = new GeneralName(GeneralName.dNSName, certData.getSubjectAlternativeNames().get(i));
        }

        GeneralNames subjectAltName = new GeneralNames(names);
        certBuilder.addExtension(Extension.subjectAlternativeName,false,subjectAltName );


        Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(certBuilder.build(contentSigner));

        /*X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=" + certData.getServerName() + ", OU=" + certData.getOu() + ", O="
                + certData.getO() + ", L=" + certData.getL() + ", ST=" + certData.getSt() + ", C=" + certData.getC()));
        certGen.setNotBefore(certData.getNotBefore());
        certGen.setNotAfter(certData.getNotAfter());
        certGen.setSubjectDN(new X500Principal("CN=" + certData.getServerName() + ", OU=" + certData.getOu() + ", O="
                + certData.getO() + ", L=" + certData.getL() + ", ST=" + certData.getSt() + ", C=" + certData.getC()));
        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm(certData.getSigAlg());

        if (certData.isCaCert()) {
            certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

            certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

            certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
                    new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage));
        }

        GeneralName[] names = new GeneralName[certData.getSubjectAlternativeNames().size() + 1];
        names[0] = new GeneralName(GeneralName.dNSName, certData.getServerName());
        for (int i = 0; i < certData.getSubjectAlternativeNames().size(); i++) {
            names[i + 1] = new GeneralName(GeneralName.dNSName, certData.getSubjectAlternativeNames().get(i));
        }

        GeneralNames subjectAltName = new GeneralNames(names);

        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);

        X509Certificate cert = certGen.generate(kp.getPrivate(), secRandom);*/

        return new X509Data(kp, (X509Certificate) certificate, certData);

    }

    /**
     * Generate a CSR based on X509
     * 
     * @param x509
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static String generateCSR(X509Data x509) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException, OperatorCreationException {
        PKCS10CertificationRequestBuilder kpGen = new PKCS10CertificationRequestBuilder(
                new org.bouncycastle.asn1.x500.X500Name(x509.getCertificate().getSubjectX500Principal().getName()),
                SubjectPublicKeyInfo.getInstance(x509.getKeyData().getPublic().getEncoded()));

        GeneralName[] sans = new GeneralName[x509.getCertInput().getSubjectAlternativeNames().size() + 1];
        sans[0] = new GeneralName(GeneralName.dNSName, x509.getCertInput().getServerName());
        for (int i = 0; i < x509.getCertInput().getSubjectAlternativeNames().size(); i++) {
            sans[i + 1] = new GeneralName(GeneralName.dNSName, x509.getCertInput().getSubjectAlternativeNames().get(i));
        }

        GeneralNames subjectAltName = new GeneralNames(sans);
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltName.toASN1Primitive());

        kpGen.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(x509.getCertInput().getSigAlg());
        ContentSigner signer = csBuilder.build(x509.getKeyData().getPrivate());
        org.bouncycastle.pkcs.PKCS10CertificationRequest request = kpGen.build(signer);

        Base64 encoder = new Base64(67);
        String b64 = encoder.encodeToString(request.getEncoded()).trim();
        b64 = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64 + "\n-----END CERTIFICATE REQUEST-----\n";

        return b64;
    }

    /**
     * Parse a PEM file into a certificate
     * 
     * @param b64Cert
     * @return
     * @throws Exception
     */
    public static X509Certificate string2cert(String b64Cert) throws Exception {
        // System.out.println(b64Cert);
        // System.out.println("");
        b64Cert = b64Cert.replace("\n", "");
        // System.out.println(b64Cert);
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(b64Cert));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }

    public static X509Certificate pem2cert(String pem) throws Exception {
        if (!pem.startsWith("-")) {
            pem = new String(java.util.Base64.getDecoder().decode(pem));
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }

    /**
     * Generate a PEM from a certificate
     * 
     * @param cert
     * @return
     * @throws Exception
     */
    public static String exportCert(X509Certificate cert) throws Exception {

        Base64 encoder = new Base64(64);

        String b64 = encoder.encodeToString(cert.getEncoded());

        b64 = "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n";

        return b64;
    }

    /**
     * Expot and base64 encode a private key
     * 
     * @param pk
     * @return
     * @throws Exception
     */
    public static String exportKey(PrivateKey pk) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter out = new PrintWriter(baos);

        PemWriter pem = new PemWriter(out);
        pem.writeObject(new PKCS8Generator(PrivateKeyInfo.getInstance(pk.getEncoded()), null));
        pem.close();
        out.flush();
        out.close();

        return new String(baos.toByteArray());
    }

    /**
     * Import a signed certificate into the keystore for an existing keypair
     * 
     * @param x509
     * @param b64cert
     * @throws CertificateException
     * @throws UnsupportedEncodingException
     * @throws KeyStoreException
     */
    public static void importSignedCert(X509Data x509, String b64cert)
            throws CertificateException, UnsupportedEncodingException, KeyStoreException {
        String pemCert = new String(java.util.Base64.getDecoder().decode(b64cert));
        ByteArrayInputStream bais = new ByteArrayInputStream(pemCert.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        x509.setCertificate((X509Certificate) c.iterator().next());
    }

    /**
     * Import a PEM encoded certificate into the keystore
     * 
     * @param ks
     * @param ksPass
     * @param alias
     * @param pemCert
     * @throws CertificateException
     * @throws UnsupportedEncodingException
     * @throws KeyStoreException
     */
    public static void importCertificate(KeyStore ks, String ksPass, String alias, String pemCert)
            throws CertificateException, UnsupportedEncodingException, KeyStoreException {
        Collection<? extends java.security.cert.Certificate> c = pem2certs(pemCert);

        if (c.size() > 1) {
            int j = 0;
            Iterator<? extends java.security.cert.Certificate> i = c.iterator();
            while (i.hasNext()) {
                Certificate certificate = (Certificate) i.next();
                if (j == 0) {
                    ks.setCertificateEntry(alias, certificate);
                } else {
                    ks.setCertificateEntry(alias + "-" + j, certificate);
                }
                j++;
            }
        } else {
            ks.setCertificateEntry(alias, c.iterator().next());
        }

    }

    private static Collection<? extends java.security.cert.Certificate> pem2certs(String pemCert)
            throws UnsupportedEncodingException, CertificateException {

        if (!pemCert.startsWith("-")) {
            pemCert = new String(java.util.Base64.getDecoder().decode(pemCert));
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(pemCert.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return c;
    }

    /**
     * Import a certificate into the keystore
     * 
     * @param ks
     * @param ksPass
     * @param alias
     * @param cert
     * @throws CertificateException
     * @throws UnsupportedEncodingException
     * @throws KeyStoreException
     */
    public static void importCertificate(KeyStore ks, String ksPass, String alias, X509Certificate cert)
            throws CertificateException, UnsupportedEncodingException, KeyStoreException {

        ks.setCertificateEntry(alias, cert);

    }

    /**
     * Save full X509 data key into the keystore
     * 
     * @param ks
     * @param ksPass
     * @param alias
     * @param x509
     * @throws KeyStoreException
     */
    public static void saveX509ToKeystore(KeyStore ks, String ksPass, String alias, X509Data x509)
            throws KeyStoreException {
        ks.setKeyEntry(alias, x509.getKeyData().getPrivate(), ksPass.toCharArray(),
                new Certificate[] { x509.getCertificate() });
    }

    /**
     * Base64 Encode the keystore
     * 
     * @param ks
     * @param ksPassword
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static String encodeKeyStore(KeyStore ks, String ksPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, ksPassword.toCharArray());
        return java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static void importKeyPairAndCert(KeyStore ks, String ksPass, String alias, String privateKeyEncoded,
            String certEncoded) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException,
            InvalidKeySpecException {

        String privateKeyPEM = new String(java.util.Base64.getDecoder().decode(privateKeyEncoded));

        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----",
                "");// .trim();//.replaceAll("[\n,\r]", "").trim();
        byte[] pkBytes = org.bouncycastle.util.encoders.Base64.decode(privateKeyPEM);
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(pkBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey unencryptedPrivateKey = kf.generatePrivate(kspec);

        // System.out.println(privateKeyPEM);

        // PrivateKey privateKey = PrivateKeyFactory.createKey(new
        // ByteArrayInputStream(java.util.Base64.getDecoder().decode(privateKeyEncoded)));

        String pemEncodedCert = new String(java.util.Base64.getDecoder().decode(certEncoded));
        Collection<? extends Certificate> certs = pem2certs(pemEncodedCert);

        ks.setKeyEntry(alias, unencryptedPrivateKey, ksPass.toCharArray(),
                new Certificate[] { certs.iterator().next() });

    }

    public static void importKeyPairAndCertPem(KeyStore ks, String ksPass, String alias, String privateKeyPEM,
            String pemEncodedCert) throws IOException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");// .trim();//.replaceAll("[\n,\r]", "").trim();
        byte[] pkBytes = org.bouncycastle.util.encoders.Base64.decode(privateKeyPEM);
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(pkBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey unencryptedPrivateKey = kf.generatePrivate(kspec);

        // System.out.println(privateKeyPEM);

        // PrivateKey privateKey = PrivateKeyFactory.createKey(new
        // ByteArrayInputStream(java.util.Base64.getDecoder().decode(privateKeyEncoded)));

        Collection<? extends Certificate> certs = pem2certs(pemEncodedCert);

        ks.setKeyEntry(alias, unencryptedPrivateKey, ksPass.toCharArray(),
                new Certificate[] { certs.iterator().next() });

    }

    public static KeyStore decodeKeystore(String base64EncodedKS, String ksPassword) throws KeyStoreException {
        ByteArrayInputStream bais = new ByteArrayInputStream(java.util.Base64.getDecoder().decode(base64EncodedKS));
        KeyStore newKS = KeyStore.getInstance("PKCS12");
        try {
            newKS.load(bais, ksPassword.toCharArray());
            return newKS;
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            return null;
        }
    }

    public static boolean keystoresEqual(KeyStore ks1, KeyStore ks2, String ksPassword) {

        try {
            HashSet<String> checked = new HashSet<String>();

            Enumeration<String> ks1Aliases = ks1.aliases();

            while (ks1Aliases.hasMoreElements()) {
                String alias1 = ks1Aliases.nextElement();
                X509Certificate cert1 = (X509Certificate) ks1.getCertificate(alias1);

                if (cert1 != null) {
                    X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias1);
                    if (cert2 == null) {
                        return false;
                    } else if (!Arrays.equals(cert1.getSignature(), cert2.getSignature())) {
                        return false;
                    } else {
                        checked.add(alias1);
                    }
                } else {
                    SecretKey key1 = (SecretKey) ks1.getKey(alias1, ksPassword.toCharArray());
                    SecretKey key2 = (SecretKey) ks2.getKey(alias1, ksPassword.toCharArray());
                    if (key2 == null) {
                        return false;
                    } else if (!Arrays.equals(key1.getEncoded(), key2.getEncoded())) {
                        return false;
                    } else {
                        checked.add(alias1);
                    }
                }
            }

            Enumeration<String> ks2Aliases = ks2.aliases();
            while (ks2Aliases.hasMoreElements()) {
                if (!checked.contains(ks2Aliases.nextElement())) {
                    // doesn't matter the content, its failed
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            return false;
        }

    }

    public static Map<String, String> exportCerts(KeyStore ks, String ksPwd) throws Exception {
        Map<String, String> certs = new HashMap<String, String>();

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert != null) {
                if (ks.getKey(alias, ksPwd.toCharArray()) == null) {
                    certs.put(alias, CertUtils.exportCert(cert));
                }
            }
        }

        return certs;
    }

    public static boolean isCertExpiring(X509Certificate cert, int daysOut) {
        DateTime expiresOn = new DateTime(cert.getNotAfter());
        DateTime checkExpires = new DateTime().plusDays(daysOut);

        return checkExpires.isAfter(expiresOn);
    }

    public static KeyStore mergeCaCerts(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        KeyStore cacerts = KeyStore.getInstance(KeyStore.getDefaultType());
        String cacertsPath = System.getProperty("javax.net.ssl.trustStore");
        if (cacertsPath == null) {
            cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
        }
        
        cacerts.load(new FileInputStream(cacertsPath), null);
        
        Enumeration<String> enumer = cacerts.aliases();
        while (enumer.hasMoreElements()) {
            String alias = enumer.nextElement();
            java.security.cert.Certificate cert = cacerts.getCertificate(alias);
            if (cert != null) {
                ks.setCertificateEntry(alias, cert);
            }
        }

        enumer = ks.aliases();
        while (enumer.hasMoreElements()) {
            String alias = enumer.nextElement();
            java.security.cert.Certificate cert = ks.getCertificate(alias);
            if (cert != null) {
                cacerts.setCertificateEntry(alias, cert);
            }
        }

        return cacerts;
    }
}