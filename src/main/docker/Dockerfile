FROM ubuntu:18.04

MAINTAINER Tremolo Security, Inc. - Docker <docker@tremolosecurity.com>

ENV JDK_VERSION=1.8.0 \
    ARTIFACT_DEPLOY_VERSION=1.0.0 

LABEL io.k8s.description="Platform for deploying kubernetes artifacts" \
      io.k8s.display-name="Kubernetes Artifact Deployer" 

RUN apt-get update;apt-get -y install openjdk-8-jdk-headless curl apt-transport-https gnupg && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update; apt-get install -y kubectl ; apt-get -y upgrade;apt-get clean;rm -rf /var/lib/apt/lists/*; \
    groupadd -r artifactdeploy -g 433 && \
    mkdir /usr/local/artifactdeploy && \
    useradd -u 431 -r -g artifactdeploy -d /usr/local/artifactdeploy -s /sbin/nologin -c "Artifact Deployment Docker image user" artifactdeploy && \
    curl https://nexus.tremolo.io/repository/releases/com/tremolosecurity/kubernetes/artifact-deployment/$ARTIFACT_DEPLOY_VERSION/artifact-deployment-$ARTIFACT_DEPLOY_VERSION.jar -o /usr/local/artifactdeploy/artifact-deploy.jar && \
    chown -R artifactdeploy:artifactdeploy /usr/local/artifactdeploy 

USER 431

CMD ["/usr/bin/java", "-jar", "/usr/local/artifactdeploy/artifact-deploy.jar"]