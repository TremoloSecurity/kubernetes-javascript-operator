# kubernetes-javascript-operator
Framework for Building Operators in Javascript

## Objectives

* Provide the building blocks for building an operator out of JavaScript and Java.  
* The base container can be reused across operator implementations
* JavaScript is attached as `ConfigMap`s for the image
* Image is built on a Java base, providing access to both JavaScript functions and Java's built in capabilities
* Provide low level access to the api server with some error handling
* Watch single object type on startup, let additional watches be registered in code
* Compatibility With Red Hat Operator Lifecycle Manager

## Why JavaScript?

* Well known across IT environments
* Does not require pre-compiled binaries
* Native support for JSON
* Runs in Java

## Why Java?

* Robust APIs
* Well tested and trusted in IT
* Flexible

## Creating an Operator

The JavaScript operator is an application written in Java that loads JavaScript files.  In order to create an operator you must have at least one javascript file with a function called `on_watch`.  Here is an example from the OpenUnison operator (https://github.com/TremoloSecurity/openunison-k8s-operator/blob/master/src/main/js/operator.js):

```
//Called by controller
function on_watch(k8s_event) {
    print("in js : "  + k8s_event);
    event_json = JSON.parse(k8s_event);
    k8s_obj = event_json['object'];
    cfg_obj = k8s_obj['spec'];
    
    if (event_json["type"] === "ADDED") {
        generate_openunison_secret(event_json);
        create_static_objects();

        

    } else if (event_json["type"] === "MODIFIED") {
        generate_openunison_secret(event_json);
        update_k8s_deployment();

    } else if (event_json["type"] === "DELETED") {
        delete_k8s_deployment();
    }
}
```

You can have multiple javascript files to organize your code, they just all need to be in the same directory.  See OpenUnison's operator for an example of how to build your operator - https://github.com/TremoloSecurity/openunison-k8s-operator/tree/master/src/main/js

## Testing Your Operator

Once of the benefits of using JavaScript and Java as the base for your operator is the ability to test from outside the cluster easily.  This cuts down your development cycles by minimizing time creating containers, deploying and updating in your cluster.  

1. Create a directory to store your Kubernetes information (certificates, tokens, etc).
2. Create a directory in this directory called `extra`
3. Create a service account, grant it the appropriate privileges then get its token by running `kubectl describe secret sa-name-token-xxxxx`.  Once you have the token, store it in a file called `token` in the directory from step 1
4. Get your cluster's CA certificate, store it in a file called `ca.pem` in the directory from step 1
5. Download the operator jar from https://nexus.tremolo.io/repository/betas/com/tremolosecurity/kubernetes/javascript-operator/1.0.0/javascript-operator-1.0.0.jar

Once you are ready to test, run the operator locally:

`java -jar /path/to/javascript-operator-1.0.0.jar -tokenPath /path/to/k8s-operator/token -rootCaPath /path/to/k8s-operator/ca.pem -configMaps /path/to/k8s-operator/extra -kubernetesURL https://192.168.2.132:6443 -namespace openunison -apiGroup 'openunison.tremolo.io/v1' -objectType openunisons -jsPath '/path/to/openunison-k8s-operator/src/main/js'`

As you create/update/delete your custom resources that are being watched you'll see the output.

## Deploying Your Operator

First, create a Docker image.  The Dockerfile for the OpenUnison operator is a good start - https://github.com/TremoloSecurity/openunison-k8s-operator/blob/master/Dockerfile.  Once you have pushed your Dockerfile into a registry, create a `Deployment` that will run in your namespace.  The example from OpenUnison is a good starting point - https://github.com/TremoloSecurity/openunison-k8s-operator/blob/master/src/main/yaml/openunison-operator-deployment.yaml.

## Toolbox

From inside of your JavaScript there are multiple objects meant to make it easier to interact with the api server.  See the `docs` folder for a detailed description of the objects definitions.

### k8s

The `k8s` object maintains a "connection" to the api server.  Internally it trusts the api server's certificate and is pre-configured to work with the api token for the service account of the container.  
