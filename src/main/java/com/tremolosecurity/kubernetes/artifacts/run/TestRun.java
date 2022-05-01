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
import java.io.FileReader;
import java.io.InputStreamReader;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import com.tremolosecurity.kubernetes.artifacts.util.K8sUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * TestRun
 */
public class TestRun {

    public static void main(String[] args) throws Exception {
        /*K8sUtils k8s = new K8sUtils("/home/mlb/tmp/k8s/token","/home/mlb/tmp/k8s/master.pem","/home/mlb/tmp/k8s/extracerts","https://k8s-installer-master.tremolo.lan:6443");

        Map<String,String> inputParams = new HashMap<String,String>();

        BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream("/home/mlb/tmp/k8s/props")));
        String line;
        while ((line = in.readLine()) != null) {
            String name = line.substring(0,line.indexOf('='));
            String val = line.substring(line.indexOf('=') + 1);
            inputParams.put(name, val);
        }*/



        Security.addProvider(new BouncyCastleProvider());
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        //engine.getBindings(ScriptContext.ENGINE_SCOPE).put("k8s", k8s);
        //engine.getBindings(ScriptContext.ENGINE_SCOPE).put("inProp", inputParams);
        engine.eval(new FileReader("/Users/mlb/Documents/testxml.js"));

        
    }
}