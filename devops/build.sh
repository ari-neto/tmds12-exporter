#!/bin/bash
# source ~/creds/projects/ferryman-slack
source ~/creds/projects/devops
APP="tmds-exporter"
CONT_NAME="tmds-exporter"
VERSION="0.0.0"

APP=tmselabs
DOCKER_REGISTRY='179239123302.dkr.ecr.us-east-1.amazonaws.com'
REGISTRY_CRED=~/creds/registry_aws_techbr-demo_credential.json
SC_HOST='container-security.tmselabs.com'
case "$1" in
    scan)
        figlet "scanning image"
        scan --smartcheck-host $SC_HOST --smartcheck-user $SC_USER --smartcheck-password $SC_PASSWORD --image-pull-auth $(cat $REGISTRY_CRED) --insecure-skip-tls-verify $DOCKER_REGISTRY/$APP/$CONT_NAME:latest | jq .
        figlet "list vulnerabilities"
        list-vulnerabilities --smartcheck-host $SC_HOST --smartcheck-user $SC_USER --smartcheck-password $SC_PASSWORD --insecure-skip-tls-verify $DOCKER_REGISTRY/$APP/$CONT_NAME:latest
        ;;
    build)
        figlet "docker build"
        echo " "
        docker build -t $CONT_NAME .
        echo " "
        ;;
    deploy)
        figlet "deploy"
        echo " "
        kubectl delete pod $(kubectl get pods -n tmds-exporter --no-headers=true|grep -i tmds-exporter|awk '{ print $1}') -n tmds-exporter
        echo " "
        ;;
    ci)
        #docker login -u dasalabsreg -p 'psInLHnF=RptpwEKXXkOnS5WIxIcgSA5' dasalabsreg.azurecr.io
        $(aws ecr get-login --no-include-email --region us-east-1)
        figlet "docker build"
        echo " "
        docker build -t $CONT_NAME .
#        docker build -t -f Dockerfile_alpine $CONT_NAME-alpine .
        figlet "docker tag"
        echo " "
        docker tag $CONT_NAME:latest $DOCKER_REGISTRY/$APP/$CONT_NAME:$VERSION
        docker tag $CONT_NAME:latest $DOCKER_REGISTRY/$APP/$CONT_NAME:latest
#        docker tag $CONT_NAME-alpine:latest $DOCKER_REGISTRY/$APP/$CONT_NAME:alpine-$VERSION
#        docker tag $CONT_NAME-alpine:latest $DOCKER_REGISTRY/$APP/$CONT_NAME:alpine-latest
        echo " "
        figlet "docker login"
        echo " "
        docker login -u $DOCKER_USER -p $DOCKER_PASSWORD $DOCKER_REGISTRY
        echo " "
        figlet "docker push"
        echo " "
        docker push $DOCKER_REGISTRY/$APP/$CONT_NAME:$VERSION
        docker push $DOCKER_REGISTRY/$APP/$CONT_NAME:latest
        ;;
    cd)
        #docker login -u dasalabsreg -p 'psInLHnF=RptpwEKXXkOnS5WIxIcgSA5' dasalabsreg.azurecr.io
        figlet "kubernetes deploy"
        echo " "
        figlet "namespace"
        echo " "
        kubectl apply -f devops/k8s/namespace.yaml
        echo " "
        figlet "secrets"
        echo " "
        kubectl apply -f devops/k8s/secrets.yaml
        echo " "
        figlet "deploy"
        echo " "
        kubectl apply -f devops/k8s/deployment.yaml
        echo " "
        figlet "services"
        echo " "
        kubectl apply -f devops/k8s/services.yaml
        echo " "
        figlet "networkpolicy"
        echo " "
        kubectl apply -f devops/k8s/networkpolicy.yaml
        ;;
    *)
        echo "build.sh scan   --> scan and list container vulnerabilities"
        echo "build.sh build  --> build container locally"
        echo "build.sh deploy --> redeploy container locally on k8s"
        echo "build.sh ci     --> build and push the container"
        echo "build.sh cd     --> deploy on k8s"
        ;;
esac
