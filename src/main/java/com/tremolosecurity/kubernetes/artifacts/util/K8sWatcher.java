package com.tremolosecurity.kubernetes.artifacts.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Map;

import javax.script.Invocable;
import javax.script.ScriptEngine;

import com.tremolosecurity.kubernetes.artifacts.obj.HttpCon;
import com.tremolosecurity.kubernetes.artifacts.run.Controller;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class K8sWatcher {
    K8sUtils k8s;
    String lastProcessedResource;
    HashSet<String> processedVersions;
    String functionName;
    HashSet<String> expired;

    public K8sWatcher(K8sUtils k8s, String functionName) {
        this.k8s = k8s;
        this.processedVersions = new HashSet<String>();
        this.functionName = functionName;
        this.expired = new HashSet<String>();
    }

    public boolean isValidUri(String uri) {
        // load up the existing objects
        Map resp;
        try {
            resp = k8s.callWS(uri);
            int responseCode = (int) resp.get("code");
            return (responseCode == 200);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        
    }

    public void watchUri(String uri) throws Exception {
        processExistingObjects(uri);

        JSONParser parser = new JSONParser();
        HttpCon http = null;

        try {
            http = this.k8s.createClient();

            boolean keepRunning = true;

            while (keepRunning) {
                StringBuilder sb = new StringBuilder().append(k8s.getK8sUrl()).append(uri)
                        .append("?watch=true&timeoutSeconds=30");
                if (this.lastProcessedResource != null) {
                    sb.append("&resourceVersion=").append(this.lastProcessedResource);
                }
                String url = sb.toString();
                System.out.println(url);
                HttpGet watchApi = new HttpGet(url);
                String token = this.k8s.getAuthorizationToken();
                if (token != null) {
                    watchApi.addHeader("Authorization", "Bearer " + token);
                }

                CloseableHttpResponse resp = null;

                try {
                    resp = http.getHttp().execute(watchApi);
                } catch (IOException e) {
                    System.out.println("Unable to contact api server");
                    e.printStackTrace();
                    System.out.println("Sleeping for 2 seconds...");
                    Thread.sleep(2000);
                    System.out.println("Trying again");
                    continue;

                }

                BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));

                String line = null;
                while ((line = in.readLine()) != null) {
                    JSONObject event = (JSONObject) parser.parse(line);
                    JSONObject object = (JSONObject) event.get("object");
                    
                    if (object.get("kind") != null && object.get("kind").equals("Status")) {
                        if (object.get("status").equals("Failure")) {
                            System.out.println("Watch failed : " + line);
                            if(object.get("reason").equals("Expired")) {
                                this.expired.add(this.lastProcessedResource);
                                this.lastProcessedResource = null;
                                break;
                            }
                        }
                    }

                    String resourceVersion = getResourceVersion(object );
                    
                    if (resourceVersion == null) {
                        
                        throw new Exception("No resource " + line);

                    } else {
                        if (this.processedVersions.contains(resourceVersion)) {
                            System.out
                                    .println("Resource " + resourceVersion + "  has already been processed, skipping");
                        } else {
                            if (! this.processedVersions.contains(resourceVersion)) {
                                this.processedVersions.add(resourceVersion);
                            }

                            if (! this.expired.contains(resourceVersion)) {
                                this.lastProcessedResource = resourceVersion;
                            } else {
                                this.lastProcessedResource = null;
                            }
                            
                            
                            String eventType = (String) event.get("type");
                            if (eventType.equalsIgnoreCase("MODIFIED")) {
                                if (hasObjectChanged((JSONObject) event.get("object"))) {

                                    // process the object
                                    try {
                                        processEvent(event);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                } else {
                                    System.out.println("No change, skipping");
                                }
                            } else {
                                // process the object
                                try {
                                    processEvent(event);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }

                }

                resp.close();
                watchApi.abort();
                
            }

        } catch (Exception e) {

            e.printStackTrace();
        } finally {
            if (http != null) {
                try {
                    http.getHttp().close();
                } catch (Exception e) {
                    // do nothing
                }
                http.getBcm().close();
            }
        }

    }

    private void processExistingObjects(String uri) throws Exception {

        // load up the existing objects
        Map resp = k8s.callWS(uri);
        int responseCode = (int) resp.get("code");
        if (responseCode != 200) {
            throw new Exception("Unable to load " + uri + " - " + resp);
        }

        JSONParser parser = new JSONParser();
        JSONObject root = (JSONObject) parser.parse((String) resp.get("data"));
        JSONArray items = (JSONArray) root.get("items");
        for (Object o : items) {
            JSONObject item = (JSONObject) o;

            String resourceVersion = this.getResourceVersion(item);
            if (resourceVersion == null) {
                System.out.println("skipping " + item);
                continue;
            }

            this.processedVersions.add(resourceVersion);
            this.lastProcessedResource = resourceVersion;
            if (hasStatus(item)) {

                // has been processed at least once
                if (hasObjectChanged(item)) {
                    // The object has been updated since the operator was last run
                    JSONObject change = new JSONObject();
                    change.put("object", item);
                    change.put("type", "MODIFIED");

                    // process the object
                    try {
                        processEvent(change);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }

            } else {
                // no status, so it needs to be added
                JSONObject add = new JSONObject();
                add.put("object", item);
                add.put("type", "ADDED");

                // process the object
                try {
                    processEvent(add);
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        }

    }

    public static boolean hasStatus(JSONObject object) {
        return object.get("status") != null;
    }

    public static boolean hasObjectChanged(JSONObject cr)
            throws ParseException, NoSuchAlgorithmException, UnsupportedEncodingException {
        if (!hasStatus(cr)) {
            // no status, nothing to compare against so it has changed
            return true;
        }

        JSONObject chkObj = generateCleanCR(cr);

        String digestBase64 = generateCheckSum(chkObj);

        String existingDigest = (String) ((JSONObject) cr.get("status")).get("digest");
        return !existingDigest.equals(digestBase64);
    }

    private static String generateCheckSum(JSONObject chkObj)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String jsonForChecksum = chkObj.toJSONString();
        MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(jsonForChecksum.getBytes("UTF-8"), 0, jsonForChecksum.getBytes("UTF-8").length);
        byte[] digestBytes = digest.digest();
        String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
        return digestBase64;
    }

    private static JSONObject generateCleanCR(JSONObject cr) throws ParseException {
        JSONParser parser = new JSONParser();

        JSONObject chkObj = new JSONObject();
        chkObj.put("apiVersion", cr.get("apiVersion"));
        chkObj.put("kind", cr.get("kind"));
        chkObj.put("spec", cr.get("spec"));

        JSONObject metadata = (JSONObject) parser.parse(((JSONObject) cr.get("metadata")).toJSONString());

        metadata.remove("creationTimestamp");
        metadata.remove("generation");
        metadata.remove("resourceVersion");
        metadata.remove("managedFields");

        chkObj.put("metadata", metadata);
        return chkObj;
    }

    private String getResourceVersion(JSONObject cr) {

        JSONObject metadata = (JSONObject) (JSONObject) cr.get("metadata");

        String resourceVersion = (String) metadata.get("resourceVersion");

        if (resourceVersion == null) {
            System.out.println("unexpected json - " + cr.toString());
            return null;
        } else {
            return resourceVersion;
        }
    }

    private String processEvent(JSONObject event) throws Exception {
        K8sUtils localK8s = new K8sUtils(Controller.tokenPath, Controller.rootCaPath, Controller.configMaps,
                Controller.kubernetesURL);
        ScriptEngine localEngine = Controller.initializeJS(Controller.jsPath, Controller.namespace, localK8s);
        localK8s.setEngine(localEngine);

        Invocable invocable = (Invocable) localEngine;

        boolean error = false;

        String result = null;

        try {
            result = (String) invocable.invokeFunction(functionName, event.toString());
        } catch (Throwable t) {
            System.err.println("Error on watch - " + event.toString());
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

        if (event.get("type").equals("MODIFIED") || event.get("type").equals("ADDED")) {
            JSONObject cr = generateCleanCR((JSONObject) event.get("object"));

            String digestBase64 = generateCheckSum(cr);
            ((JSONObject) cr.get("metadata")).put("resourceVersion",
                    (String) ((JSONObject) ((JSONObject) event.get("object")).get("metadata")).get("resourceVersion"));
            JSONObject patch = generateJsonStatus(result, digestBase64, localK8s.getAdditionalStatuses());
            cr.put("status", patch);
            String selfLink = (String) ((JSONObject) ((JSONObject) event.get("object")).get("metadata"))
                    .get("selfLink");

            this.k8s.putWS(selfLink + "/status", cr.toJSONString());

        }

        return result;

    }

    private JSONObject generateJsonStatus(String errorMessage, String digest, Map<String, Object> additionalStatuses) {
        JSONObject patch = new JSONObject();

        patch.put("conditions", new JSONObject());
        ((JSONObject) patch.get("conditions")).put("lastTransitionTime",
                DateTimeFormat.forPattern("yyyy-MM-dd hh:mm:ssz").print(new DateTime()));
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

    private void addToJson(JSONObject root, String name, Object value) {
        if (value instanceof String) {
            root.put(name, value);
        } else if (value instanceof Map) {
            JSONObject newRoot = new JSONObject();
            root.put(name, newRoot);
            Map<String, Object> rootSet = (Map<String, Object>) value;
            for (String keyName : rootSet.keySet()) {
                addToJson(newRoot, keyName, rootSet.get(keyName));
            }
        } else {
            System.out.println("Unknown type" + value);
        }
    }
}
