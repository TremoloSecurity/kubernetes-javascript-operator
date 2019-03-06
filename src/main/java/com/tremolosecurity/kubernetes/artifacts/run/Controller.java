//    Copyright 2019 Tremolo Security, Inc.
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

package com.tremolosecurity.kubernetes.artifacts.run;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import com.tremolosecurity.kubernetes.artifacts.util.K8sUtils;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Controller
 */
public class Controller {

    static boolean stillWatching;

    public static void main(String[] args) throws Exception {


        Runtime.getRuntime().addShutdownHook(new Thread()  { 
            public void run() { 
                System.out.println("Cought the shutdown hook");
                stillWatching = false;
            }    
        }); 


        Options options = new Options();
        options.addOption("tokenPath", true, "The path to the token to use when communicating with the API server");
        options.addOption("rootCaPath", true,
                "The path to the certificate athority PEM file for the kubrnetes API server");
        options.addOption("configMaps", true,
                "The full path to a directory containing additional certificates to trust");
        options.addOption("kubernetesURL", true, "The URL for the kubernetes api server");
        options.addOption("jsPath", true, "Path to JavaScript files to load");
        options.addOption("apiGroup", true, "version and group");
        options.addOption("namespace", true, "namespace");
        options.addOption("objectType", true, "CRD type");
        
        options.addOption("help", false, "Prints this message");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args, true);

        stillWatching = true;

        if (args.length == 0 || cmd.hasOption("help")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("Kubernetes Javascript Operator Options", options);
        } else {
            String tokenPath = loadOption(cmd, "tokenPath", options);
            String rootCaPath = loadOption(cmd, "rootCaPath", options);
            String configMaps = loadOption(cmd, "configMaps", options);
            String kubernetesURL = loadOption(cmd, "kubernetesURL", options);
            String jsPath = loadOption(cmd,"jsPath",options);

            String apiGroup = loadOption(cmd, "apiGroup", options);
            String namespace = loadOption(cmd, "namespace", options);
            String objectType = loadOption(cmd, "objectType", options);
            

            K8sUtils k8s = new K8sUtils(tokenPath, rootCaPath, configMaps, kubernetesURL);

            

            Security.addProvider(new BouncyCastleProvider());
            ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("k8s", k8s);
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("k8s_namespace",namespace);
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("js",engine);
            
            File[] scripts = new File(jsPath).listFiles();
            for (File script : scripts) {
                if (script.getAbsolutePath().endsWith(".js")) {
                    System.out.println("Loading Script : '" + script.getAbsolutePath() + "'");
                    engine.eval(new BufferedReader(new InputStreamReader(script.toURL().openStream())));
                }
            } 

            k8s.setEngine(engine);
            while (stillWatching) {
                runWatch(apiGroup, namespace, objectType, k8s);
            }
            // URL scriptURL = new URL(installScriptURL);
            // engine.eval(new BufferedReader(new
            // InputStreamReader(scriptURL.openStream())));
        }
    }

    private static void runWatch(String apiGroup, String namespace, String objectType, K8sUtils k8s)
            throws Exception, ParseException {
        String uri = "/apis/" + apiGroup + "/namespaces/" + namespace + "/" + objectType;

        Map res = k8s.callWS(uri);
        String jsonObj = (String) res.get("data");
        
        JSONObject root = (JSONObject) new JSONParser().parse(jsonObj);
        String resourceVersion = (String) ((JSONObject) root.get("metadata")).get("resourceVersion");
        System.out.println(resourceVersion);

        //uri = uri + "?watch=true&resourceVersion=" + resourceVersion + "&fieldSelector=metadata.name=" + objectName;
        uri = uri + "?watch=true&resourceVersion=" + resourceVersion;
        k8s.watchURI(uri,"on_watch");
    }

    static String loadOption(CommandLine cmd,String name,Options options) {
		String val = cmd.getOptionValue(name);
		if (val == null) {
			System.err.println("Could not find option '" + name + "'");
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnison Kubernetes Artifact Deployer", options );
			System.exit(1);
			return null;
		} else {
			return val;
		}
	}
}