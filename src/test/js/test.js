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

print("Loading CertUtils");
var CertUtils = Java.type("com.tremolosecurity.kubernetes.artifacts.util.CertUtils");
print("Creating certInfo");
certInfo = {
    "serverName":"openunison.openunison.svc.cluster.local",
    "ou":"dev",
    "o":"tremolo",
    "l":"alexandria",
    "st":"virginia",
    "c":"us",
    "caCert":false
}

print("generating certificate");
var x509data = CertUtils.createCertificate(certInfo);

print("printing cert");
print(CertUtils.exportCert(x509data.getCertificate()));
print(CertUtils.generateCSR(x509data));

print(k8s.callWS("/api/v1/namespaces").data);