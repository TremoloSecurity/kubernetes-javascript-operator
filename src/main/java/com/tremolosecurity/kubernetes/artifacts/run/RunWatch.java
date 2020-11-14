package com.tremolosecurity.kubernetes.artifacts.run;

import com.tremolosecurity.kubernetes.artifacts.util.K8sUtils;
import com.tremolosecurity.kubernetes.artifacts.util.K8sWatcher;

/**
 * RunWatch
 */
public class RunWatch implements Runnable {
    K8sUtils k8s;
    boolean running;
    String uri;
    String functionName;

    boolean closeFromError;

    K8sWatcher watcher;

    public RunWatch(K8sUtils k8s, String uri, String functionName) {
        this.running = true;
        this.k8s = k8s;
        this.uri = uri;
        this.functionName = functionName;
        this.watcher = new K8sWatcher(k8s, this.functionName);
    }

    public boolean isRightVersion() {
        return this.watcher.isValidUri(this.uri);
    }

    @Override
    public void run() {
        closeFromError = false;
        while (running) {

            try {
                
                watcher.watchUri(uri);
            } catch (Exception e) {
                System.out.println("Error watching");
                e.printStackTrace();
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e1) {
                    
                }
            }

            /*try {
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
                    this.closeFromError = true;
                }

            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                
            }*/
            
        }

        if (closeFromError) {
            System.out.println("Closing from a previous error");
            System.exit(1);
        }

    }

    public void stopThread() {
        this.running = false;
    }
    
}