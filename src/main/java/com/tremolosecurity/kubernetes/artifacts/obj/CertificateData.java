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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * CertificateData
 */
public class CertificateData {

    String serverName = "";
	String ou = "";
	String o = "";
	String l = "";
	String st = "";
	String c = "";

	int size = 2048;
	boolean rsa = true;

	String sigAlg = "SHA256withRSA";
	Date notBefore = new Date(System.currentTimeMillis());
	Date notAfter = new Date(System.currentTimeMillis() + 315360000000L);
	
	SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");

    boolean caCert;
    
    List<String> subjectAlternativeNames;

    public static String escpaeRDN(String rdn) {
		return rdn.replaceAll("[,]", "\\\\,").replaceAll("[+]", "\\\\+").replaceAll("[=]", "\\\\=");
    }
    
    public CertificateData() {
        this.subjectAlternativeNames = new ArrayList<String>();
    }

    public boolean isCaCert() {
		return this.caCert;
	}

	public void setCaCert(boolean caCert) {
		this.caCert = caCert;
	}


	
	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = CertificateData.escpaeRDN(serverName);
	}

	public String getOu() {
		return ou;
	}

	public void setOu(String ou) {
		this.ou = CertificateData.escpaeRDN(ou);
	}

	public String getO() {
		return o;
	}

	public void setO(String o) {
		this.o = CertificateData.escpaeRDN(o);
	}

	public boolean isRsa() {
		return rsa;
	}

	public void setRsa(boolean rsa) {
		this.rsa = rsa;
	}

	public String getSigAlg() {
		return sigAlg;
	}

	public void setSigAlg(String sigAlg) {
		this.sigAlg = sigAlg;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}
	
	public String getNotBeforeStr() {
		return sdf.format(notBefore);
	}

	public void setNotBeforeStr(String notBefore) throws Exception {
		this.notBefore = sdf.parse(notBefore);
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	
	public String getNotAfterStr() {
		return sdf.format(notAfter);
	}

	public void setNotAfterStr(String notAfter) throws Exception {
		
			this.notAfter = sdf.parse(notAfter);
		
	}

	public String getL() {
		return l;
	}

	public void setL(String l) {
		this.l = CertificateData.escpaeRDN(l);
	}

	public String getSt() {
		return st;
	}

	public void setSt(String st) {
		this.st = CertificateData.escpaeRDN(st);
	}

	public String getC() {
		return c;
	}

	public void setC(String c) {
		this.c = CertificateData.escpaeRDN(c);
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
    }
    
    /**
     * @return the subjectAlternativeNames
     */
    public List<String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
	}
	
	/**
	 * @param subjectAlternativeNames the subjectAlternativeNames to set
	 */
	public void setSubjectAlternativeNames(LinkedHashMap vals) {

		this.subjectAlternativeNames = new ArrayList<String>();
		for (Object o : vals.values()) {
			this.subjectAlternativeNames.add((String) o);
		}
		
		//this.subjectAlternativeNames.addAll(subjectAlternativeNames);
	}
}