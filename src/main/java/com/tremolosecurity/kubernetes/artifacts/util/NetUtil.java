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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.tremolosecurity.kubernetes.artifacts.obj.HttpCon;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseFactory;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;

/**
 * NetUtil
 */
public class NetUtil {

    private static KeyStore ks;
    private static String ksPassword;
    private static KeyManagerFactory kmf;
    private static Registry<ConnectionSocketFactory> httpClientRegistry;
    private static RequestConfig globalHttpClientConfig;
    private static String pathToMoreCerts;

    public static void reinit() throws Exception {
        initialize(pathToMoreCerts);
    }

    public static void initialize(String pathToMoreCerts) throws Exception {
        NetUtil.pathToMoreCerts = pathToMoreCerts;
        ksPassword = UUID.randomUUID().toString();
        ks = KeyStore.getInstance("PKCS12");
        ks.load(null, ksPassword.toCharArray());

        File moreCerts = new File(pathToMoreCerts);
        if (moreCerts.exists() && moreCerts.isDirectory()) {
            for (File certFile : moreCerts.listFiles()) {
                System.out.println("Processing - '" + certFile.getAbsolutePath() + "'");
                if (certFile.isDirectory() || !certFile.getAbsolutePath().toLowerCase().endsWith(".pem")) {
                    System.out.println("not a pem, sipping");
                    continue;
                }
                String certPem = new String(Files.readAllBytes(Paths.get(certFile.getAbsolutePath())),
                        StandardCharsets.UTF_8);
                String alias = certFile.getName().substring(0, certFile.getName().indexOf('.'));

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

        initssl();
    }

    public static void initssl()
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, ksPassword.toCharArray());

        SSLContext sslctx = SSLContexts.custom().loadTrustMaterial(ks).loadKeyMaterial(ks, ksPassword.toCharArray())
                .build();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslctx,
                SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

        PlainConnectionSocketFactory sf = PlainConnectionSocketFactory.getSocketFactory();
        httpClientRegistry = RegistryBuilder.<ConnectionSocketFactory>create().register("http", sf)
                .register("https", sslsf).build();

        globalHttpClientConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.IGNORE_COOKIES)
                .setRedirectsEnabled(false).setAuthenticationEnabled(false).build();
    }

    public static void addCertToStore(X509Certificate cert, String alias) throws KeyStoreException {
        ks.setCertificateEntry(alias, cert);
    }


    private static HttpCon createClient() throws Exception {
        ArrayList<Header> defheaders = new ArrayList<Header>();
        defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

        BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(httpClientRegistry);

        int numSecconds = 30;

        RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
                .setConnectTimeout(numSecconds * 1000)
                .setConnectionRequestTimeout(numSecconds * 1000)
                .setSocketTimeout(numSecconds * 1000).build();

        CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultHeaders(defheaders)
                .setDefaultRequestConfig(rc).build();


        HttpCon con = new HttpCon();
        con.setBcm(bhcm);
        con.setHttp(http);

        return con;

    }


    public static String downloadFile(String url) throws Exception {
        if (url.toLowerCase().startsWith("file://")) {
            return downloadFileFromFS(url);
        } else {
            return downloadFileFromWeb(url);
        }
    }

    private static String downloadFileFromFS(String url) throws Exception {
        
        URL urlObj = new URL(url);
        URLConnection conn = urlObj.openConnection();
        String ret = null;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)))
        {
            ret = reader.lines().collect(Collectors.joining("\n"));
        }

        return ret;
    
    }

    /**
     * Downloads a file from the given URL
     * 
     * @param url
     * @return
     * @throws IOException
     */
    public static String downloadFileFromWeb(String url) throws Exception {
        HttpGet get = new HttpGet(url);
        HttpCon con = createClient();

        try {
            HttpResponse resp = con.getHttp().execute(get);
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resp.getEntity().getContent(), StandardCharsets.UTF_8)))
        {
            return reader.lines().collect(Collectors.joining("\n"));
        }
        } finally {
            try {
                con.getHttp().close();
            } catch (Exception e) {
                //do nothig
            }
            con.getBcm().shutdown();
            con.getBcm().close();
        }


        
    }

    /**
     * Determine your IP address
     * @return
     * @throws SocketException
     */
    public static String whatsMyIP() throws SocketException {
        Enumeration<NetworkInterface> enumer = NetworkInterface.getNetworkInterfaces();
        while (enumer.hasMoreElements()) {
            NetworkInterface ni = enumer.nextElement();
            Enumeration<InetAddress> enumeri = ni.getInetAddresses();
            while (enumeri.hasMoreElements()) {
                InetAddress addr = enumeri.nextElement();
                if (! addr.getHostAddress().startsWith("127")) {
                    return addr.getHostAddress();
                }
            }
        }

        return "";
    }
}