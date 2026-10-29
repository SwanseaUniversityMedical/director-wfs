bash script assumes we're starting with a completely empty vm, but should also check that things aren't already installed.
vm options are ubuntu 20.04 or newer, debian 12 or newer, and osx (apple).

takes 8 args as input: 
	1. dns name
	2. s3 endpoint (should include protocol and port) [optional]
	3. s3 access key [optional]
	4. s3 secret key [optional]
	5. s3 use tls [optional]
	6. signing cert full chain (or path to such on local disk (.crt or .pem)) [optional]
	7. signing cert key (or path to such on local disk (.key)) [optional]
	8. dev password to use/set on all deployments [optional]

of the args, if the optional ones arent provided we need to do more things:
	for 2, 3, 4, and 5; 
	- a) look in ~/.aws/credentials and parse the file in there
	- b) if there isn't any file there, try the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT environment variables
	- c) if the endpoint doesn't include a protocol, try and figure out if it's http or https
	- c) if any of those are still empty, fail the script run

	for 6 and 7;
	- a) generate a self-signed root CA that can sign other certs
	- b) then use the self-signed root to generate an intermediate cert that can sign other certs if they're subdomains of the dns name arg
	- c) create a file that concats the intermediate and root ca (intermediate at top of file, root at bottom, one empty line between them) to make a full chain

	for 8;
	- generate random passwords for argo and grafana

- make sure kind will work for apple silicon by doing
# kind doesn't work on apple silicon if this is set
export DOCKER_DEFAULT_PLATFORM=
set DOCKER_DEFAULT_PLATFORM=

- next, install (or check installed):
	- docker
	- kubectl
	- kind
	- helm

- clone a git repo (public, hardcoded in script)
	- this brings down a structure like
		- director-wfs/
			- files/
				- argo/
					- app.yaml
					- project.yaml
					- repo.yaml
				- deps/
					- argo.yaml
					- coredns.yaml
					- ingress-nginx.yaml
			- clean-up.sh (deletes the cluster)
			- kind-config.yaml
			- README.md

- change into the repo directory and do `kind create cluster --config=kind-config.yaml`

- use helm to install ingress-nginx, cilium
- kubectl apply to patch coredns

- in the `files/deps/argo.yaml` file, 
	- template the given dns name everywhere it needs to be, putting "argocd." on the front of the dns name given as an arg 
	- template the argocdServerAdminPassword based on the value given as arg or the random one generated if not provided

- use helm to install argo, using that templated/patched file as override values

- create the namespaces "tesk-stack" and "cert-manager"

- then we need to generate some yaml to put in the k8s cluster
	- certificates:
		- create a k8s secret called "ca-key-pair" and put it in the cert-manager namespace
			- needs to have data with keys called `tls.crt` (the full chain) and `tls.key` (the key)
	- tesk s3 secret:
		- create a k8s secret called "aws-secret" and put it in the tesk-stack namespace
			- needs to look like the below, using the aws creds args from the script input
				```
				apiVersion: v1
				kind: Secret
				metadata:
				  name: aws-secret
				stringData:
				  config: |
				    [default]
				    endpoint_url=PROTOCOL://host:port
				  credentials: |
				    [default]
				    aws_access_key_id=S3_ACCESS_KEY
				    aws_secret_access_key=S3_SECRET_ACCESS_KEY
				```

- wait up to 10 minutes until argo, cilium, and ingress-nginx are completely ready

- kubectl apply files/argo/project.yaml and files/argo/repo.yaml

- in the `files/argo/app.yaml` file, do more yaml templating/patching using args from the bash script
	- save the templated file to the local disk
	- then kubectl apply that templated file


- wait for all components of this app to be ready

- output to console the:
	- argo dns addr
	- argo admin user
	- argo admin pw
	- grafana dns addr
	- grafana admin user
	- grafana admin pw
	- tesk dns addr
	- path to fully templated app.yaml file



