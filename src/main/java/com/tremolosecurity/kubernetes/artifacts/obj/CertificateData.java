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
	Date notAfter = new Date(System.currentTimeMillis() + 31536000000L);

	SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");

	boolean caCert;

	List<String> subjectAlternativeNames;

	/**
	 * Properly escaoe an an RDN in an X509 subject
	 * @param rdn
	 * @return
	 */
	public static String escpaeRDN(String rdn) {
		return rdn.replaceAll("[,]", "\\\\,").replaceAll("[+]", "\\\\+").replaceAll("[=]", "\\\\=");
	}

	/**
	 * Default constructor
	 */
	public CertificateData() {
		this.subjectAlternativeNames = new ArrayList<String>();
	}

	/**
	 * True if this certificate is for signing other certificates
	 * @return
	 */
	public boolean isCaCert() {
		return this.caCert;
	}

	/**
	 * Set to true if this certificate is meant for signing other certificates
	 * @param caCert
	 */
	public void setCaCert(boolean caCert) {
		this.caCert = caCert;
	}

	/**
	 * The server name for this certificate.  Will be used for both the CN of the subject and as a subject alternative namne
	 * @return
	 */
	public String getServerName() {
		return serverName;
	}

	/**
	 * The server name for this certificate.  Will be used for both the CN of the subject and as a subject alternative namne
	 * @param serverName
	 */
	public void setServerName(String serverName) {
		this.serverName = CertificateData.escpaeRDN(serverName);
	}

	/** 
	 * For X509 Subject
	 */
	public String getOu() {
		return ou;
	}

	public void setOu(String ou) {
		this.ou = CertificateData.escpaeRDN(ou);
	}

	/** 
	 * For X509 Subject
	 */
	public String getO() {
		return o;
	}

	/** 
	 * For X509 Subject
	 */
	public void setO(String o) {
		this.o = CertificateData.escpaeRDN(o);
	}

	/**
	 * Sets if this is an RSA or DSA certificate
	 * @return
	 */
	public boolean isRsa() {
		return rsa;
	}

	/**
	 * Gets if this is an RSA or DSA certificate
	 * @return
	 */
	public void setRsa(boolean rsa) {
		this.rsa = rsa;
	}

	/**
	 * The name of the signing algorithm
	 * @return
	 */
	public String getSigAlg() {
		return sigAlg;
	}

	/**
	 * The name of the signing algorithim
	 * @param sigAlg
	 */
	public void setSigAlg(String sigAlg) {
		this.sigAlg = sigAlg;
	}

	/**
	 * The date this certificate starts being valid
	 * @return
	 */
	public Date getNotBefore() {
		return notBefore;
	}

	/**
	 * The date this certificate starts being valid
	 * @return
	 */
	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	/**
	 * String version of not-before date
	 * @return
	 */
	public String getNotBeforeStr() {
		return sdf.format(notBefore);
	}

	/**
	 * String version of not before date
	 * @param notBefore
	 * @throws Exception
	 */
	public void setNotBeforeStr(String notBefore) throws Exception {
		this.notBefore = sdf.parse(notBefore);
	}

	/**
	 * Date this certificate expires
	 * @return
	 */
	public Date getNotAfter() {
		return notAfter;
	}

	/**
	 * Date this certificate expires
	 * @param notAfter
	 */
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	/**
	 * String version of not after
	 * @return
	 */
	public String getNotAfterStr() {
		return sdf.format(notAfter);
	}

	/**
	 * String version of not after
	 * @param notAfter
	 * @throws Exception
	 */
	public void setNotAfterStr(String notAfter) throws Exception {

		this.notAfter = sdf.parse(notAfter);

	}

	/**
	 * For X509 Subject
	 * @return
	 */
	public String getL() {
		return l;
	}

	/**
	 * For X509 Subject
	 * @param l
	 */
	public void setL(String l) {
		this.l = CertificateData.escpaeRDN(l);
	}

	/**
	 * For X509 Subject
	 * @return
	 */
	public String getSt() {
		return st;
	}

	/**
	 * For X509 Subject
	 * @param st
	 */
	public void setSt(String st) {
		this.st = CertificateData.escpaeRDN(st);
	}

	/**
	 * For X509 Subject
	 * @return
	 */
	public String getC() {
		return c;
	}

	/**
	 * For X509
	 * @param c
	 */
	public void setC(String c) {
		this.c = CertificateData.escpaeRDN(c);
	}

	/**
	 * Key size
	 * @return
	 */
	public int getSize() {
		return size;
	}

	/**
	 * key size
	 * @param size
	 */
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

		
	}
}