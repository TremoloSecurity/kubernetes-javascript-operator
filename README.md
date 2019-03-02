# kubernetes-javascript-operator
Framework for Building Operators in Javascript

## Objectives

* Provide the building blocks for building an operator out of JavaScript and Java.  
* The base container can be reused across operator implementations
* JavaScript is attached as `ConfigMap`s for the image
* Image is built on a Java base, providing access to both JavaScript functions and Java's built in capabilities
* Provide low level access to the api server with some error handling
* Watch single object on startup, let additional watches be registered in code
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

## How To...

## Toolbox

From inside of your JavaScript there are multiple objects meant to make it easier to interact with the api server.  See the `docs` folder for a detailed description of the objects definitions.

### k8s

The `k8s` object maintains a "connection" to the api server.  Internally it trusts the api server's certificate and is pre-configured to work with the api token for the service account of the container.  
