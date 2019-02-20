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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tremolosecurity.kubernetes.artifacts.obj.CertificateData;
import com.tremolosecurity.kubernetes.artifacts.obj.X509Data;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertUtils {
    static SecureRandom secRandom = new SecureRandom();

    /**
     * Generates an AES-256 SecretKey
     * @return
     * @throws Exception
     */
    public static void  createKey(KeyStore ks,String alias,String ksPassword) throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(256, secRandom);
		SecretKey sk = kg.generateKey();
		ks.setKeyEntry(alias, sk, ksPassword.toCharArray(), null);
    }
    
    public static X509Data createCertificate(Map fromjs) throws Exception {
        CertificateData data = new ObjectMapper().convertValue(fromjs, CertificateData.class);

        return createCertificate(data);
    }

    public static X509Data createCertificate(CertificateData certData) throws Exception {
		String keyAlg = "RSA";
		

		KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg);
		kpg.initialize(certData.getSize(),secRandom);
		KeyPair kp = kpg.generateKeyPair();

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=" + certData.getServerName()
				+ ", OU=" + certData.getOu() + ", O=" + certData.getO()
				+ ", L=" + certData.getL() + ", ST=" + certData.getSt()
				+ ", C=" + certData.getC()));
		certGen.setNotBefore(certData.getNotBefore());
		certGen.setNotAfter(certData.getNotAfter());
		certGen.setSubjectDN(new X500Principal("CN=" + certData.getServerName()
				+ ", OU=" + certData.getOu() + ", O=" + certData.getO()
				+ ", L=" + certData.getL() + ", ST=" + certData.getSt()
				+ ", C=" + certData.getC()));
		certGen.setPublicKey(kp.getPublic());
		certGen.setSignatureAlgorithm(certData.getSigAlg());

		if (certData.isCaCert()) {
		certGen.addExtension(X509Extensions.BasicConstraints, true,
				new BasicConstraints(true));

		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
			KeyUsage.keyCertSign));

		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
			new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage));		
        }
        
        GeneralName[] names = new GeneralName[certData.getSubjectAlternativeNames().size() + 1];
        names[0] = new GeneralName(GeneralName.dNSName, certData.getServerName());
        for (int i=0;i<certData.getSubjectAlternativeNames().size();i++) {
            names[i + 1] = new GeneralName(GeneralName.dNSName, certData.getSubjectAlternativeNames().get(0));
        }

        GeneralNames subjectAltName = new GeneralNames(names);
        
        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);

		X509Certificate cert = certGen.generate(kp.getPrivate(), 
				secRandom);
		
		return new X509Data(kp,cert,certData);

    }
    
    public static String generateCSR(X509Data x509) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException {
        PKCS10CertificationRequestBuilder kpGen = new PKCS10CertificationRequestBuilder( new org.bouncycastle.asn1.x500.X500Name(x509.getCertificate().getSubjectX500Principal().getName()), SubjectPublicKeyInfo.getInstance(x509.getKeyData().getPublic().getEncoded()));

        GeneralName[] sans = new GeneralName[x509.getCertInput().getSubjectAlternativeNames().size() + 1];
        sans[0] = new GeneralName(GeneralName.dNSName,x509.getCertInput().getServerName());
        for (int i=0;i<x509.getCertInput().getSubjectAlternativeNames().size();i++) {
            sans[i+1] = new GeneralName(GeneralName.dNSName,x509.getCertInput().getSubjectAlternativeNames().get(i));
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
        b64 = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";
                
        return b64;
    }


    public static X509Certificate string2cert(String b64Cert) throws Exception {
        //System.out.println(b64Cert);
        //System.out.println("");
        b64Cert = b64Cert.replace("\n", "");
        //System.out.println(b64Cert);
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(b64Cert));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        return (X509Certificate) c.iterator().next();
    }

    public static String exportCert(X509Certificate cert) throws Exception {
		
		Base64 encoder = new Base64(64);
		
		String b64 = encoder.encodeToString(cert.getEncoded()); 
				
				
		
			b64 = "-----BEGIN CERTIFICATE-----\n" + b64
					+ "-----END CERTIFICATE-----\n";
		

		return b64;
    }
    
    public static String exportKey(PrivateKey pk) throws Exception {
        Base64 encoder = new Base64(64);
		
		String b64 = encoder.encodeToString(pk.getEncoded()); 
				
				
		
			b64 = "-----BEGIN RSA PRIVATE KEY-----\n" + b64
					+ "-----END RSA PRIVATE KEY-----\n";
		

		return b64;
    }

    public static void importSignedCert(X509Data x509,String b64cert) throws CertificateException, UnsupportedEncodingException, KeyStoreException {
        String pemCert = new String(java.util.Base64.getDecoder().decode(b64cert));
        ByteArrayInputStream bais = new ByteArrayInputStream(pemCert.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);
        x509.setCertificate((X509Certificate) c.iterator().next());
    }

    public static void importCertificate(KeyStore ks,String ksPass,String alias,String pemCert) throws CertificateException, UnsupportedEncodingException, KeyStoreException {
        ByteArrayInputStream bais = new ByteArrayInputStream(pemCert.getBytes("UTF-8"));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> c = cf.generateCertificates(bais);

        if (c.size() > 1) {
            int j = 0;
            Iterator<? extends java.security.cert.Certificate> i = c.iterator();
            while (i.hasNext()) {
                Certificate certificate = (Certificate) i.next();
                ks.setCertificateEntry(alias + "-" + j, certificate);
            }
        } else {
            ks.setCertificateEntry(alias, c.iterator().next());
        }

    }

    public static void importCertificate(KeyStore ks,String ksPass,String alias,X509Certificate cert) throws CertificateException, UnsupportedEncodingException, KeyStoreException {
        
            ks.setCertificateEntry(alias, cert);
        

    }

    public static void saveX509ToKeystore(KeyStore ks,String ksPass,String alias,X509Data x509)
            throws KeyStoreException {
        ks.setKeyEntry(alias, x509.getKeyData().getPrivate(),ksPass.toCharArray(), new Certificate[]{x509.getCertificate()});
    }

    public static String encodeKeyStore(KeyStore ks,String ksPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, ksPassword.toCharArray());
        return java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
    }
    
}