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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;

import com.tremolosecurity.kubernetes.artifacts.obj.HttpCon;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

/**
 * K8sUtils
 */
public class K8sUtils {
    String token;
    private KeyStore ks;
    private String ksPassword;
    private KeyManagerFactory kmf;
	private Registry<ConnectionSocketFactory> httpClientRegistry;
    private RequestConfig globalHttpClientConfig;
    String url;
    String pathToCaCert;

    ScriptEngine engine;

    public K8sUtils(String pathToToken,String pathToCA,String pathToMoreCerts,String apiServerURL) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        //get the token for talking to k8s
        this.token = new String(Files.readAllBytes(Paths.get(pathToToken)), StandardCharsets.UTF_8);

        this.pathToCaCert = pathToCA;

        this.ksPassword = UUID.randomUUID().toString();
        this.ks = KeyStore.getInstance("PKCS12");
        this.ks.load(null, this.ksPassword.toCharArray());


        String caCert = new String(Files.readAllBytes(Paths.get(pathToCA)), StandardCharsets.UTF_8);

        CertUtils.importCertificate(ks, ksPassword, "k8s-master", caCert);

        File moreCerts = new File(pathToMoreCerts);
        if (moreCerts.exists() && moreCerts.isDirectory()) {
            for (File certFile : moreCerts.listFiles()) {
                System.out.println("Processing - '" + certFile.getAbsolutePath() + "'");
                if (certFile.isDirectory() || ! certFile.getAbsolutePath().toLowerCase().endsWith(".pem")) {
                    System.out.println("not a pem, sipping");
                    continue;
                }
                String certPem = new String(Files.readAllBytes(Paths.get(certFile.getAbsolutePath())), StandardCharsets.UTF_8);
                String alias = certFile.getName().substring(0,certFile.getName().indexOf('.'));
                CertUtils.importCertificate(ks, ksPassword, alias, certPem);
            }
        }

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
            ks.setCertificateEntry(alias, cert);
        }
        
        this.kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(this.ks, this.ksPassword.toCharArray());

        SSLContext sslctx = SSLContexts.custom().loadTrustMaterial(this.ks).loadKeyMaterial(this.ks,this.ksPassword.toCharArray()).build();
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslctx,SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		
		PlainConnectionSocketFactory sf = PlainConnectionSocketFactory.getSocketFactory();
		this.httpClientRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
		        .register("http", sf)
		        .register("https", sslsf)
		        .build();
		
		this.globalHttpClientConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.IGNORE_COOKIES).setRedirectsEnabled(false).setAuthenticationEnabled(false).build();

        this.url = apiServerURL;

    }

    public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				this.httpClientRegistry);

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();

		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);

		return con;

	}


    public Map callWS(String uri) throws Exception {
        return callWS(uri,null,10);
    }

    public Map callWS(String uri,String testFunction,int count) throws Exception {
        
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        get.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(get);
		    String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",json);

            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(json);

                if (count > 0) {
                    System.err.println("Sleeping, then trying again");
                    Thread.sleep(10000);
                    System.err.println("trying again");
                    return callWS(uri, testFunction, --count);

                }
            }

            if (testFunction != null) {
                engine.getBindings(ScriptContext.ENGINE_SCOPE).put("check_ws_response",false);
                engine.getBindings(ScriptContext.ENGINE_SCOPE).put("ws_response_json",json);

                
                try {
                    engine.eval(testFunction);
                } catch (Throwable t) {
                    System.err.println("Unable to verify '" + uri + "' / " + json);
                    t.printStackTrace();
                    if (count > 0) {
                        System.err.println("Sleeping, then trying again");
                        Thread.sleep(10000);
                        System.err.println("trying again");
                        return callWS(uri, testFunction, --count);
    
                    }
                }

                if (! ((Boolean) engine.getBindings(ScriptContext.ENGINE_SCOPE).get("check_ws_response"))) {
                    System.err.println("Verification for '" + uri + "' failed / " + json);
                    if (count > 0) {
                        System.err.println("Sleeping, then trying again");
                        Thread.sleep(10000);
                        System.err.println("trying again");
                        return callWS(uri, testFunction, --count);
    
                    }
                }
            }


            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }

    public Map deleteWS(String uri) throws Exception {
        
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpDelete delete = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        delete.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(delete);
		    String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",json);

            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(json);
            }

            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }
    
    public Map postWS(String uri,String json) throws Exception {
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPost post = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        post.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		post.setEntity(str);

        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(post);
		    String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",jsonResponse);

            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(json);
            }

            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }

    public Map putWS(String uri,String json) throws Exception {
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPut post = new HttpPut(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        post.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		post.setEntity(str);

        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(post);
		    String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",jsonResponse);


            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(json);
            }

            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }


    public X509Certificate getCertificate(String name) throws KeyStoreException {
        return (X509Certificate) this.ks.getCertificate(name);
    }

    public String encodeMap(Map data) throws UnsupportedEncodingException {
        String vals = "";
        for (Object k : data.keySet()) {
            vals += k + "=" + data.get(k) + "\n";
        }
        vals = vals.substring(0,vals.length()-1);
        return Base64.getEncoder().encodeToString(vals.getBytes("UTF-8"));
    }

    public String processTemplate(String template,Map vars) {
        StringBuffer newConfig = new StringBuffer();
        newConfig.setLength(0);

        int begin,end;


        begin = 0;
        end = 0;

        String finalCfg = null;

        begin = template.indexOf("#[");
        while (begin > 0) {
            if (end == 0) {
                newConfig.append(template.substring(0,begin));
            } else {
                newConfig.append(template.substring(end,begin));
            }

            end = template.indexOf(']',begin + 2);

            String envVarName = template.substring(begin + 2,end);
            String value = (String) vars.get(envVarName);

            if (value == null) {
                value = "";
            }

            

            newConfig.append(value);

            begin = template.indexOf("#[",end + 1);
            end++;
        }

        if (end != 0) {
            newConfig.append(template.substring(end));
        }

        return newConfig.toString();
    }

    public void kubectlCreate(String data) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec(new String[]{"kubectl","--token=" + this.token ,"--server=" + this.url ,"--certificate-authority=" + this.pathToCaCert ,"create","-f","-"});

        new Thread() {
            public void run() {
                BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                try {
                    while ((line = in.readLine()) != null) {
                        System.out.println(line);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }.start();

        new Thread() {
            public void run() {
                BufferedReader in = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                String line;
                try {
                    while ((line = in.readLine()) != null) {
                        System.err.println(line);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }.start();

        PrintStream out = new PrintStream(p.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data.getBytes("UTF-8"))));
        String line;
        while ((line = in.readLine()) != null) {
            out.println(line);
        }

        out.close();
        System.out.println("waiting for completion");

        p.waitFor();

    }

    /**
     * @param engine the engine to set
     */
    public void setEngine(ScriptEngine engine) {
        this.engine = engine;
    }

    /**
     * @return the engine
     */
    public ScriptEngine getEngine() {
        return engine;
    }
    
}