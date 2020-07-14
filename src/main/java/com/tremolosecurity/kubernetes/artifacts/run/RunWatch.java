package com.tremolosecurity.kubernetes.artifacts.run;

import com.tremolosecurity.kubernetes.artifacts.util.K8sUtils;

/**
 * RunWatch
 */
public class RunWatch implements Runnable {
    K8sUtils k8s;
    boolean running;
    String uri;
    String functionName;

    public RunWatch(K8sUtils k8s, String uri, String functionName) {
        this.running = true;
        this.k8s = k8s;
        this.uri = uri;
        this.functionName = functionName;
    }

    @Override
    public void run() {
        while (running) {
            try {
                k8s.watchURI(uri, functionName);
            } catch (Throwable t) {
                System.err.println("Error watching " + uri + "re-querying");
                t.printStackTrace(System.err);

                String newUri = uri.substring(0, uri.indexOf('?'));
                try {
                    this.uri = Controller.findResourceVersion(k8s, newUri);
                } catch (Exception e) {
                    System.err.println("Could not get latest resource version uri");
                    e.printStackTrace();
                    this.running = false;
                }

            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                
            }
            
        }

    }

    public void stopThread() {
        this.running = false;
    }
    
}