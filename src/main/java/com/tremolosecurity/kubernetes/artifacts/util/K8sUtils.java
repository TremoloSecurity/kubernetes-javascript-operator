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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.imageio.stream.FileImageInputStream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.tremolosecurity.kubernetes.artifacts.obj.HttpCon;
import com.tremolosecurity.kubernetes.artifacts.run.Controller;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
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
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;

/**
 * K8sUtils
 * 
 * Utilities for interacting with the Kubernetes API server
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
    String caCert;
    ScriptEngine engine;

    private Map<String,Object> additionalStatuses;

    private boolean openShift;

    private Map<String,String> extraCerts;

    static HashSet<String> processedVersions = new HashSet<String>();

    boolean fromKc;
    String pathToToken;

    /**
     * Initialization
     * 
     * @param pathToToken
     * @param pathToCA
     * @param pathToMoreCerts
     * @param apiServerURL
     * @throws Exception
     */
    public K8sUtils(String pathToToken, String pathToCA, String pathToMoreCerts, String apiServerURL) throws Exception {
        // get the token for talking to k8s
        this.pathToToken = pathToToken;
        this.token = null;
        this.fromKc = false;

        this.pathToCaCert = pathToCA;

        this.url = apiServerURL;

        this.extraCerts = new HashMap<String,String>();

        this.ksPassword = UUID.randomUUID().toString();
        this.ks = KeyStore.getInstance("PKCS12");
        this.ks.load(null, this.ksPassword.toCharArray());

        if (System.getenv().get("KUBECONFIG") != null) {
            this.fromKc = true;
            String pathToKubeConfig = System.getenv("KUBECONFIG");
            System.out.println("******* OVERRIDING WITH KUBECONFIG FROM '" + pathToKubeConfig + "' ******************");
            
            
            KubeConfig kc = KubeConfig.loadKubeConfig(new InputStreamReader(new FileInputStream(pathToKubeConfig)));
            String context = kc.getCurrentContext();
            this.token = kc.getAccessToken();

            this.url = kc.getServer();

            if (token == null) {
                if (kc.getClientKeyData() != null) {
                    String pemKey = new String(Base64.getDecoder().decode(kc.getClientKeyData()));
                    String pemCert = new String(Base64.getDecoder().decode(kc.getClientCertificateData()));

                    CertUtils.importKeyPairAndCertPem(this.ks, this.ksPassword, "k8sclient", pemKey, pemCert);
                }

                
            }

            if (kc.getCertificateAuthorityData() != null) {
                CertUtils.importCertificate(ks, ksPassword, "k8s-master", new String(Base64.getDecoder().decode(kc.getCertificateAuthorityData())));
            }
        } else {
            caCert = new String(Files.readAllBytes(Paths.get(pathToCA)), StandardCharsets.UTF_8);
            CertUtils.importCertificate(ks, ksPassword, "k8s-master", caCert);
        }

        

        

        File moreCerts = new File(pathToMoreCerts);
        if (moreCerts.exists() && moreCerts.isDirectory()) {
            for (File certFile : moreCerts.listFiles()) {
                System.out.println("Processing - '" + certFile.getAbsolutePath() + "'");
                if (certFile.isDirectory() || !certFile.getAbsolutePath().toLowerCase().endsWith(".pem")) {
                    System.out.println("not a pem, skipping");
                    continue;
                }
                String certPem = new String(Files.readAllBytes(Paths.get(certFile.getAbsolutePath())),
                        StandardCharsets.UTF_8);
                String alias = certFile.getName().substring(0, certFile.getName().indexOf('.'));
                this.extraCerts.put(alias, certPem);
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

        SSLContext sslctx = SSLContexts.custom().loadTrustMaterial(this.ks)
                .loadKeyMaterial(this.ks, this.ksPassword.toCharArray()).build();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslctx,
                SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

        PlainConnectionSocketFactory sf = PlainConnectionSocketFactory.getSocketFactory();
        this.httpClientRegistry = RegistryBuilder.<ConnectionSocketFactory>create().register("http", sf)
                .register("https", sslsf).build();

        this.globalHttpClientConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.IGNORE_COOKIES)
                .setRedirectsEnabled(false).setAuthenticationEnabled(false).build();

        

        this.openShift = false;

        Map<String,Object> res = this.callWS("/apis");
        String json = (String) res.get("data");
        

        JSONParser parser = new JSONParser();
        JSONObject root = (JSONObject) parser.parse(json);
        JSONArray groups = (JSONArray) root.get("groups");

        for (Object obj : groups) {
            JSONObject group = (JSONObject) obj;
            String name = (String) group.get("name");
            if (name.toLowerCase().contains("openshift")) {
                this.openShift = true;
                break;
            }
        }

        additionalStatuses = new HashMap<String,Object>();
    }

    /**
     * Generate an HTTP client pre-configured with the container's service-account
     * token and trust of the api server's certificate
     * 
     * @return
     * @throws Exception
     */
    public HttpCon createClient() throws Exception {
        ArrayList<Header> defheaders = new ArrayList<Header>();
        defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

        BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(this.httpClientRegistry);

        RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
                .build();

        CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultHeaders(defheaders)
                .setDefaultRequestConfig(rc).build();

        HttpCon con = new HttpCon();
        con.setBcm(bhcm);
        con.setHttp(http);

        return con;

    }

    /**
     * Call a kubernetes web service via GET
     * 
     * @param uri
     * @return
     * @throws Exception
     */
    public Map callWS(String uri) throws Exception {
        return callWS(uri, null, 10);
    }

    /**
     * Watch a Kubernetes object based on its URI
     * 
     * @param uri
     * @throws Exception
     */
    public void watchURI(String uri, String functionName) throws Exception {


        

        K8sUtils localK8s = new K8sUtils(Controller.tokenPath, Controller.rootCaPath, Controller.configMaps,
                Controller.kubernetesURL);
        ScriptEngine localEngine = Controller.initializeJS(Controller.jsPath, Controller.namespace, localK8s);
        localK8s.setEngine(localEngine);
        StringBuffer b = new StringBuffer();

        System.out.println(uri);

        System.out.println("Is OpenShift : " + localK8s.isOpenShift());

        b.append(this.getK8sUrl()).append(uri);
        HttpGet get = new HttpGet(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {

            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            get.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }

        HttpCon con = this.createClient();

        try {
            HttpResponse resp = con.getHttp().execute(get);

            BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));

            String line = null;
            while ((line = in.readLine()) != null) {

                JSONParser parser = new JSONParser();
                JSONObject json = (JSONObject) parser.parse(line);

                
                JSONObject cr = (JSONObject) json.get("object");
                JSONObject chkObj = new JSONObject();
                chkObj.put("apiVersion", cr.get("apiVersion"));
                chkObj.put("kind", cr.get("kind"));
                chkObj.put("spec", cr.get("spec"));

                JSONObject metadata = (JSONObject) parser.parse(((JSONObject)cr.get("metadata")).toJSONString());

                String resourceVersion = (String) metadata.get("resourceVersion");

                if (resourceVersion == null) {
                    System.out.println("unexpected json - " + line);
                    throw new Exception("No resourceVersion, restartinig watch");
                }

                System.out.println("Resource Version - " + resourceVersion + " - " + processedVersions.contains(resourceVersion));

                if (processedVersions.contains(resourceVersion)) {
                    System.out.println("Resource - " + resourceVersion + " - already processed, skipping");
                    continue;
                } else {
                    processedVersions.add(resourceVersion);
                }

                metadata.remove("creationTimestamp");
                metadata.remove("generation");
                metadata.remove("resourceVersion");
                metadata.remove("managedFields");
                

                chkObj.put("metadata", metadata);
                
                String jsonForChecksum = chkObj.toJSONString();
                MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                digest.update(jsonForChecksum.getBytes("UTF-8"),0,jsonForChecksum.getBytes("UTF-8").length);
                byte[] digestBytes = digest.digest();
                String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
                    
                if (json.get("type").equals("MODIFIED")) {
                    if (json.get("object") != null && ((JSONObject) json.get("object")).get("status") != null && ((JSONObject) ((JSONObject) json.get("object")).get("status")).get("digest") != null) {
                        String existingDigest = (String) ((JSONObject) ((JSONObject) json.get("object")).get("status")).get("digest");
                        if (existingDigest.equals(digestBase64)) {
                            continue;
                        }
                    }
                }

                Invocable invocable = (Invocable) localEngine;

                boolean error = false;


                String result = null;
                
                try {
                    System.out.println("Starting javascript");
                    result = (String) invocable.invokeFunction(functionName, line);
                    System.out.println("javascript completed");
                } catch (Throwable t) {
                    System.err.println("Error on watch - " + uri);
                    t.printStackTrace(System.err);
                    error = true;
                }

                if (error) {
                    if (result != null) {
                        result = "error-" + result;
                    } else {
                        result = "error";
                    }
                }

                System.out.println("Creating status for '" + json.get("type") + "'");
                if (json.get("type").equals("MODIFIED") || json.get("type").equals("ADDED")) {
                    System.out.println("Creating status");
                    JSONObject patch = this.generateJsonStatus(result, digestBase64,localK8s.getAdditionalStatuses());
                    cr.put("status",patch);

                    String selfUri = uri;
                    if (selfUri.contains("?")) { 
                        selfUri = selfUri.substring(0,selfUri.indexOf('?'));
                    }

                    System.out.println("Patching : '" + selfUri + "'");
                    System.out.println("New status : " + cr.toJSONString());

                    //String selfLink = (String)  ((JSONObject) ((JSONObject) json.get("object")).get("metadata")).get("selfLink");

                    this.putWS(selfUri + "/status", cr.toJSONString());
                

                }

                
                

            }

        } finally {
            if (con != null) {
                con.getBcm().shutdown();
            }
        }

    }

    private JSONObject generateJsonStatus(String errorMessage,String digest, Map<String, Object> additionalStatuses) {
        JSONObject patch = new JSONObject();
        
        patch.put("conditions", new JSONObject());
        ((JSONObject) patch.get("conditions")).put("lastTransitionTime", DateTimeFormat.forPattern("yyyy-MM-dd hh:mm:ssz").print(new DateTime()));
        patch.put("digest", digest);

        if (errorMessage == null) {
            ((JSONObject) patch.get("conditions")).put("status", "True");
            ((JSONObject) patch.get("conditions")).put("type", "Completed");
        } else {
            ((JSONObject) patch.get("conditions")).put("status", "True");
            ((JSONObject) patch.get("conditions")).put("type", "Failed");
            ((JSONObject) patch.get("conditions")).put("status", "True");
            ((JSONObject) patch.get("conditions")).put("reason", errorMessage);
        }

        for (String extraStatus : additionalStatuses.keySet()) {
            this.addToJson(patch, extraStatus, additionalStatuses.get(extraStatus));
        }

        return patch;
    }

    private void addToJson(JSONObject root,String name,Object value) {
        if (value instanceof String) {
            root.put(name,value);
        } else if (value instanceof Map) {
            JSONObject newRoot = new JSONObject();
            root.put(name, newRoot);
            Map<String,Object> rootSet = (Map<String,Object>) value;
            for (String keyName : rootSet.keySet()) {
                addToJson(newRoot, keyName, rootSet.get(keyName));
            }
        } else {
            System.out.println("Unknown type" + value);
        }
    }

    /**
     * GET an API via its URI, with a test function for success and a number of
     * attempted retries
     * 
     * @param uri
     * @param testFunction
     * @param count
     * @return
     * @throws Exception
     */
    public Map callWS(String uri, String testFunction, int count) throws Exception {

        StringBuffer b = new StringBuffer();

        b.append(this.getK8sUrl()).append(uri);
        HttpGet get = new HttpGet(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {
            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            get.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }

        HttpCon con = this.createClient();
        try {
            HttpResponse resp = con.getHttp().execute(get);
            String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code", resp.getStatusLine().getStatusCode());
            ret.put("data", json);

            if (count >= 0
                    && (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299)) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(json);

                if (count > 0) {
                    System.err.println("Sleeping, then trying again");
                    Thread.sleep(10000);
                    System.err.println("trying again");
                    return callWS(uri, testFunction, --count);

                }
            }

            if (testFunction != null && ! testFunction.isEmpty()) {
                engine.getBindings(ScriptContext.ENGINE_SCOPE).put("check_ws_response", false);
                engine.getBindings(ScriptContext.ENGINE_SCOPE).put("ws_response_json", json);

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

                if (!((Boolean) engine.getBindings(ScriptContext.ENGINE_SCOPE).get("check_ws_response"))) {
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
        return deleteWS(uri,true);
    }

    /**
     * DELETE a Kubernetes object
     * 
     * @param uri
     * @param ignoreNotFound
     * @return
     * @throws Exception
     */
    public Map deleteWS(String uri,boolean ignoreNotFound) throws Exception {

        StringBuffer b = new StringBuffer();

        b.append(this.getK8sUrl()).append(uri);
        HttpDelete delete = new HttpDelete(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {
            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            delete.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }

        HttpCon con = this.createClient();
        try {
            HttpResponse resp = con.getHttp().execute(delete);
            String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code", resp.getStatusLine().getStatusCode());
            ret.put("data", json);

            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                if (! (resp.getStatusLine().getStatusCode() == 404 && ignoreNotFound)) {
                    System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                    System.err.println(json);
                }
            }

            return ret;
        } finally {
            if (con != null) {
                con.getBcm().shutdown();
            }
        }
    }

    /**
     * POST to an API URI
     * 
     * @param uri
     * @param json
     * @return
     * @throws Exception
     */
    public Map postWS(String uri, String json) throws Exception {
        StringBuffer b = new StringBuffer();

        b.append(this.getK8sUrl()).append(uri);
        HttpPost post = new HttpPost(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {
            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            post.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }

        StringEntity str = new StringEntity(json, ContentType.APPLICATION_JSON);
        post.setEntity(str);

        HttpCon con = this.createClient();
        try {
            HttpResponse resp = con.getHttp().execute(post);
            String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code", resp.getStatusLine().getStatusCode());
            ret.put("data", jsonResponse);

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


    /**
     * PUT to a URI
     * 
     * @param uri
     * @param json
     * @return
     * @throws Exception
     */
    public Map patchWS(String uri, String json) throws Exception {
        StringBuffer b = new StringBuffer();

        b.append(this.getK8sUrl()).append(uri);
        HttpPatch patch = new HttpPatch(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {
            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            patch.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }
        patch.setEntity(EntityBuilder.create().setContentType(ContentType.create("application/merge-patch+json")).setText(json).build());



        HttpCon con = this.createClient();
        try {
            HttpResponse resp = con.getHttp().execute(patch);
            String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code", resp.getStatusLine().getStatusCode());
            ret.put("data", jsonResponse);

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

    /**
     * PUT to a URI
     * 
     * @param uri
     * @param json
     * @return
     * @throws Exception
     */
    public Map putWS(String uri, String json) throws Exception {
        StringBuffer b = new StringBuffer();

        b.append(this.getK8sUrl()).append(uri);
        HttpPut post = new HttpPut(b.toString());
        String ltoken = this.getAuthorizationToken();
        if (ltoken != null) {
            b.setLength(0);
            b.append("Bearer ").append(ltoken);
            post.addHeader(new BasicHeader("Authorization", "Bearer " + ltoken));
        }
        StringEntity str = new StringEntity(json, ContentType.APPLICATION_JSON);
        post.setEntity(str);

        HttpCon con = this.createClient();
        try {
            HttpResponse resp = con.getHttp().execute(post);
            String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code", resp.getStatusLine().getStatusCode());
            ret.put("data", jsonResponse);

            if (resp.getStatusLine().getStatusCode() < 200 || resp.getStatusLine().getStatusCode() > 299) {
                System.err.println("Problem calling '" + uri + "' - " + resp.getStatusLine().getStatusCode());
                System.err.println(jsonResponse);
            }

            return ret;
        } finally {
            if (con != null) {
                con.getBcm().shutdown();
            }
        }
    }

    /**
     * Returns a certificate from the internal keystore
     * 
     * @param name
     * @return
     * @throws KeyStoreException
     */
    public X509Certificate getCertificate(String name) throws KeyStoreException {
        return (X509Certificate) this.ks.getCertificate(name);
    }

    /**
     * Base64 encode a Map of name/value pairs
     * 
     * @param data
     * @return
     * @throws UnsupportedEncodingException
     */
    public String encodeMap(Map data) throws UnsupportedEncodingException {
        String vals = "";
        for (Object k : data.keySet()) {
            vals += k + "=" + data.get(k) + "\n";
        }
        vals = vals.substring(0, vals.length() - 1);
        return Base64.getEncoder().encodeToString(vals.getBytes("UTF-8"));
    }

    /**
     * Simple template processor replacing name/value pairs from the map to anything
     * enclused in #[] so #[MY_VALUE] would be replaced with the value from the map
     * associated with the key MY_VALUE
     * 
     * @param template
     * @param vars
     * @return
     */
    public String processTemplate(String template, Map vars) {
        StringBuffer newConfig = new StringBuffer();
        newConfig.setLength(0);

        int begin, end;

        begin = 0;
        end = 0;

        String finalCfg = null;

        begin = template.indexOf("#[");
        while (begin > 0) {
            if (end == 0) {
                newConfig.append(template.substring(0, begin));
            } else {
                newConfig.append(template.substring(end, begin));
            }

            end = template.indexOf(']', begin + 2);

            String envVarName = template.substring(begin + 2, end);
            String value = (String) vars.get(envVarName);

            if (value == null) {
                value = "";
            }

            newConfig.append(value);

            begin = template.indexOf("#[", end + 1);
            end++;
        }

        if (end != 0) {
            newConfig.append(template.substring(end));
        }

        return newConfig.toString();
    }

    /**
     * Run kubectl create with the data passed in using the service account of the
     * container
     * 
     * @param data
     * @throws IOException
     * @throws InterruptedException
     */
    public void kubectlCreate(String data) throws IOException, InterruptedException {
        String ltoken = this.getAuthorizationToken();
        Process p = Runtime.getRuntime().exec(new String[] { "kubectl", "--token=" + ltoken, "--server=" + this.getK8sUrl(),
                "--certificate-authority=" + this.pathToCaCert, "create", "-f", "-" });

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

    public String json2yaml(String json) throws IOException {
        JsonNode jsonNodeTree = new ObjectMapper().readTree(json);
        String jsonAsYaml = new YAMLMapper().writeValueAsString(jsonNodeTree);
        return jsonAsYaml;

    }

    public String getCaCert() {
        return this.caCert;
    }

    public boolean isOpenShift() {
        return this.openShift;
    }
    

    /**
     * @return the additionalStatuses
     */
    public Map<String, Object> getAdditionalStatuses() {
        return additionalStatuses;
    }

    public KeyStore getKs() {
        return this.ks;
    }

    public String getKsPassword() {
        return this.ksPassword;
    }

    public Map<String,String> getExtraCerts() {
        return this.extraCerts;
    }

    public String getK8sUrl() {
        if (this.url.equalsIgnoreCase("https://kubernetes.default.svc.cluster.local")) {
            //we want to use the default URL.  Instead of using it, we'll build it from
            //the environment variables
            return new StringBuilder().append("https://").append(System.getenv("KUBERNETES_SERVICE_HOST")).append(":").append(System.getenv("KUBERNETES_SERVICE_PORT")).toString();
        } else {
            return this.url;
        }
    }

    public String getAuthorizationToken() throws IOException {
        if (this.fromKc) {
            return this.token;
        } else {
            return new String(Files.readAllBytes(Paths.get(pathToToken)), StandardCharsets.UTF_8);
        }
    }
}