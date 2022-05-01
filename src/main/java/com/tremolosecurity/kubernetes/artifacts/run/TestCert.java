package com.tremolosecurity.kubernetes.artifacts.run;

import java.io.FileOutputStream;
import java.util.LinkedHashMap;

import com.tremolosecurity.kubernetes.artifacts.obj.CertificateData;
import com.tremolosecurity.kubernetes.artifacts.obj.X509Data;
import com.tremolosecurity.kubernetes.artifacts.util.CertUtils;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi.SHA256withRSA;
import org.joda.time.DateTime;

public class TestCert {
    public static void main(String[] args) throws Exception {
        System.out.println("here");
        CertificateData cd = new CertificateData();
        cd.setCaCert(true);
        cd.setRsa(true);
        cd.setNotBefore(new DateTime().toDate());
        cd.setNotAfter(new DateTime().plusDays(365).toDate());
        cd.setServerName("k8sou.apps.192-168-2-144.nip.io");
        cd.setOu("testx");
        cd.setO("test");
        cd.setSigAlg("SHA256withRSA");
        cd.setSize(2048);
        cd.setL("test");
        cd.setC("test");
        cd.setSt("test");
        cd.setSubjectAlternativeNames(new LinkedHashMap<String,String>());
        cd.getSubjectAlternativeNames().add("k8sdb.apps.192-168-2-144.nip.io");
        X509Data res = CertUtils.createCertificate(cd);

        FileOutputStream out = new FileOutputStream("/tmp/certs/tls.key");
        out.write(CertUtils.exportKey(res.getKeyData().getPrivate()).getBytes("UTF-8"));
        out.close();

        out = new FileOutputStream("/tmp/certs/tls.crt");
        out.write(CertUtils.exportCert(res.getCertificate()).getBytes("UTF-8"));
        out.close();

        
        
    }
}