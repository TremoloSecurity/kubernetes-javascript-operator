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

package com.tremolosecurity.kubernetes.artifacts.run;

import java.io.BufferedReader;
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

/**
 * RunDeployment
 */
public class RunDeployment {

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        options.addOption("tokenPath", true, "The path to the token to use when communicating with the API server");
        options.addOption("rootCaPath", true, "The path to the certificate athority PEM file for the kubrnetes API server");
        options.addOption("extraCertsPath", true, "The full path to a directory containing additional certificates to trust");
        options.addOption("kubernetesURL", true, "The URL for the kubernetes api server");
        options.addOption("installScriptURL", true, "The url of the install javascript");
        options.addOption("secretsPath", true, "The path to the file containing all inputs");
        options.addOption("help", false, "Prints this message");
        options.addOption("deploymentTemplate",true,"URL for the kubernetes deployment template to generate final deployment yaml");

        CommandLineParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args,true);
		
		if (args.length == 0 || cmd.hasOption("help")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnison Kubernetes Artifact Deployer", options );
		} else {
            String tokenPath = loadOption(cmd, "tokenPath", options);
            String rootCaPath = loadOption(cmd,"rootCaPath",options);
            String extraCertsPath = loadOption(cmd, "extraCertsPath", options);
            String kubernetesURL = loadOption(cmd, "kubernetesURL", options);
            String installScriptURL = loadOption(cmd,"installScriptURL",options);
            String secretsPath = loadOption(cmd, "secretsPath", options);
            String deploymentTemplate = cmd.getOptionValue("deploymentTemplate");
            
            K8sUtils k8s = new K8sUtils(tokenPath,rootCaPath,extraCertsPath,kubernetesURL);

            Map<String,String> inputParams = new HashMap<String,String>();

            BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(secretsPath)));
            String line;
            while ((line = in.readLine()) != null) {
                String name = line.substring(0,line.indexOf('='));
                String val = line.substring(line.indexOf('=') + 1);
                inputParams.put(name, val);
            }

            String templateForDeployment = null;

            if (deploymentTemplate != null) {
                URL urlObj = new URL(deploymentTemplate);
                URLConnection conn = urlObj.openConnection();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) 
                {
                    templateForDeployment = reader.lines().collect(Collectors.joining("\n"));
                }
            }

            Security.addProvider(new BouncyCastleProvider());
            ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("deploymentTemplate", templateForDeployment);
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("k8s", k8s);
            engine.getBindings(ScriptContext.ENGINE_SCOPE).put("inProp", inputParams);


            k8s.setEngine(engine);


            URL scriptURL = new URL(installScriptURL);
            engine.eval(new BufferedReader(new InputStreamReader(scriptURL.openStream())));
        }
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