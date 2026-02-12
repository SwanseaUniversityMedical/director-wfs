#!/bin/bash

# kind doesn't work on apple silicon if this is set
export DOCKER_DEFAULT_PLATFORM=
set DOCKER_DEFAULT_PLATFORM=

# create kind cluster with config
kind create cluster --config=kind-config.yaml

# install cilium cni so we can use network policies to lock down tesk
helm install cilium oci://quay.io/cilium/charts/cilium --version 1.19.0 \
   --namespace kube-system \
   --set image.pullPolicy=IfNotPresent \
   --set ipam.mode=kubernetes

# install ingress-nginx
# we're just using this at the moment as it's lighter than traefik, will migrate to traefik in future
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --namespace ingress-nginx --create-namespace -f files/deps/ingress-nginx.yaml --kube-context kind-kind

# rewrite coredns
kubectl apply -f files/deps/coredns.yaml --context kind-kind

# install argo
helm repo add argo https://argoproj.github.io/argo-helm 
helm repo update
helm upgrade --install argocd argo/argo-cd -n argocd -f files/deps/argo.yaml --create-namespace --kube-context kind-kind

# wait 4 minutes for argo to be ready
echo "Waiting 4 minutes for argo to be ready to install our app"
sleep 240
# create argo project and apps
kubectl apply -f files/argo/project.yaml --context kind-kind
kubectl apply -f files/argo/repo.yaml --context kind-kind
sleep 30
kubectl apply -f files/argo/app.yaml --context kind-kind

