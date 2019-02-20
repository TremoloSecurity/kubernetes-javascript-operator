#!/bin/bash

kubectl create namespace openunison-deploy
kubectl create configmap extracerts --from-file $1 -n openunison-deploy
kubectl create secret generic input --from-file $2 -n openunison-deploy

kubectl create -f $3

kubectl get pods -n openunison-deploy --watch