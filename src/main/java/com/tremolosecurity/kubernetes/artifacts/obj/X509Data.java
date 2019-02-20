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

package com.tremolosecurity.kubernetes.artifacts.obj;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * X509Data
 */
public class X509Data {
    X509Certificate certificate;
    KeyPair keyData;
    private CertificateData certInput;

    public X509Data() {

    }

    public X509Data(KeyPair kp,X509Certificate cert,CertificateData certInput) {
        this.keyData = kp;
        this.certificate = cert;
        this.certInput = certInput;
    }

    /**
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * @return the keyData
     */
    public KeyPair getKeyData() {
        return keyData;
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * @param keyData the keyData to set
     */
    public void setKeyData(KeyPair keyData) {
        this.keyData = keyData;
    }
 
    
    /**
     * @return the certInput
     */
    public CertificateData getCertInput() {
        return certInput;
    }

    /**
     * @param certInput the certInput to set
     */
    public void setCertInput(CertificateData certInput) {
        this.certInput = certInput;
    }
}