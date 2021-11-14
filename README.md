# k8s-KMS-vault
This repository contains code to deploy secret encryption at REST via a KMS system using a HashiCorp Vault deployment.
This implementation is based on https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/. KMS is based on envelop encryption mechanism.

In particular, you will be able to enable the encryption of secrets via KMS of TLS certificates which will be used by a simple httpgo server.
So, the key components of this deployments are:
- HashiCorp Vault deployment (https://www.vaultproject.io/)
- Vault plugin (https://github.com/ttedeschi/kubernetes-vault-kms-plugin)
- httpgo: a basic HTTP server written in Go language (https://github.com/vkuznet/httpgo)

## Components details
The full workflow is described in the diagram below, taken from [oracle](https://github.com/oracle/kubernetes-vault-kms-plugin)
![](images/vaultplugin.png)

### HashiCorp Vault
Vault is an identity-based secrets and encryption management system.

### Vault KMS plugin
The Kubernetes KMS Plugin Provider for HashiCorp Vault implementation is a simple adapter that adapts calls from Kubernetes to HashiCorp Vault APIs using configuration that determines how the plugin finds the HashiCorp Vault installation. The plugin is implemented based on the Kubernetes contract as described in Implementing a KMS plugin.

### Httpgo
HTTPGO is a basic HTTP server written in Go language

## Requirements
- Kubernetes 1.10 or later
- Go 1.9 or later

## Quick start
Log into K8s master vm (for the sake of simplicity and time we will deploy a Vault server in development mode directly on the K8s master node).

### Deploy vault server (developer mode - not to be used in production)
Install and deploy Vault server in development mode
```
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault
vault server -dev 
```
The output should be:
```
WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
and starts unsealed with a single unseal key. The root token is already
authenticated to the CLI, so you can immediately begin using Vault.

You may need to set the following environment variable:

    $ export VAULT_ADDR='http://127.0.0.1:8200'

The unseal key and root token are displayed below in case you want to
seal/unseal the Vault or re-authenticate.

Unseal Key: 8XTzc+DuTplcRYzKXrgtlXhI7mdvYtSTOzKYXKsE5Os=
Root Token: <token>

Development mode should NOT be used in production installations!
```

  
### Deploy Vault KMS Plugin
Note: The KMS Plugin Provider for HashiCorp Vault must be running before starting the Kubernetes API server.

```
export GOHOME=$(go env GOPATH)
mkdir -p $GOHOME/github.com/oracle
cd $GOHOME/github.com/oracle
git clone https://github.com/ttedeschi/kubernetes-vault-kms-plugin.git
go install github.com/oracle/kubernetes-vault-kms-plugin/vault/server@latest
```

Create ```vault-plugin.yaml``` configuration file as shown in this file [vault-plugin.yaml](vault-plugin.yaml) putting the right token and the right address that you can retrieve from the output above:
```
keyNames:
  - kube-secret-enc-key
transitPath: /transit
addr: http://127.0.0.1:8200
token: <token>
```

Then run:
```
$GOHOME/bin/server -socketFile=<location of socketfile.sock> -vaultConfig=<location of vault-plugin.yaml>
```

### Enable KMS encryption in Kubernetes
The configuration of the api-server should be contained in a yaml file like this:

```
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          name: myKmsPlugin
          endpoint: unix://<location of socketfile.sock>
          cachesize: 100
          timeout: 3s
      - identity: {}
```
Change api-server configuration by modifying ```/etc/kubernetes/manifests/kube-apiserver.yaml```, inserting:
```
--encryption-provider-config=<path to encryption configuration yaml file>
```
```
- mountPath: <path to encryption configuration yaml file folder>
  name: encryption-config
  readOnly: true
```
```
- hostPath:
    path: <path to encryption configuration yaml file folder>
    type: DirectoryOrCreate
  name: encryption-config
```
The api-server should be restarted automatically by kubelet. In case of problems, debugging can be done looking at log files stored in ```/var/log/pods/kube-system_kube-apiserver*```.

### Test generic secret encryption
Data is encrypted when written to etcd. After restarting your kube-apiserver, any newly created or updated secret should be encrypted when stored. To verify, you can use the etcdctl command line program to retrieve the contents of your secret:
```
export VAULT_ADDR='http://127.0.0.1:8200'
vault secrets enable transit
kubectl create secret generic secret1 -n default --from-literal=mykey=mydata
ETCDCTL_API=3 etcdctl --endpoints=[<endpoint_ip>]:<endpoint_port> --cert=/etc/kubernetes/pki/etcd/peer.crt  --key=/etc/kubernetes/pki/etcd/peer.key --cacert=/etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/default/secret1
```
Verify the stored secret is prefixed with ```k8s:enc:kms:v1:``` which indicates the ```kms``` provider has encrypted the resulting data.
Finally, the output of the ``` kubectl get secret secret1 -o jsonpath='{.data}'``` command  should match ```mykey: bXlkYXRh```.

Now encryption via KMS is enabled.

### Test certificate encryption and use them in httpgo server
To test with certificates, create a personal certificate and put it into a secret:
``` 
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -days 365 -key ca.key -out ca.crt -subj "/CN=yourdomain.com"
kubectl create secret tls my-tls-secret --key ca.key --cert ca.crt
```
Define a configMap for the httpgo server in a ```httpgoConfigMap.yaml```
```
 apiVersion: v1
 kind: ConfigMap
 metadata:
   name: httpgo-config
   namespace: default
 data:
   httpgoConfig.json: |
    {
        "port": 8888,
        "serverkey": "/etc/certs/tls.key",
        "serverkey": "/etc/certs/tls.crt"
    }
```
And deploy it with ```kubectl apply -f httpgoConfigMap.yaml```

Then, define the deployment and service of an httpgo server that uses that configuration and that secret:
```
# create service
apiVersion: v1
kind: Service
metadata:
  name: httpgo
spec:
  type: NodePort 
  selector:
    app: httpgo
  ports:
  - port: 8888
    targetPort: 8888 
    protocol: TCP
    name: http
    nodePort: 31000
---
# create httpgo deployment
apiVersion: apps/v1 
kind: Deployment
metadata:
  name: httpgo
spec:
  selector:
    matchLabels:
      app: httpgo
  replicas: 1
  template:
    metadata:
      labels:
        app: httpgo
    spec:
      containers:
      - name: httpgo
        image: registry.cern.ch/cmsweb/httpgo@sha256:50b8811b2b9bb834457a0764c8277b6d7242a3eba0d1b76fcbbeb7f12392ab56
        command: ["/data/httpgo"]
        args: ["-config", "/etc/config/httpgoConfig.json"]  
        volumeMounts:
          - mountPath: "/etc/certs/"
            name: my-tls-secret
            readOnly: true
          - mountPath: "/etc/config"
            name: config-volume
        ports:
        - containerPort: 8888
        imagePullPolicy: Always
      volumes:
        - name: my-tls-secret
          secret:
            secretName: my-tls-secret
          volumes:
        - name: config-volume
          configMap:
            name: httpgo-config
```
And deploy it with ```kubectl apply -f httpgo.yaml```


 
## Secrets exposure in public repo with Sealed Secrets
Sealed Secrets are the solution to manage secrets in version control systems: https://github.com/bitnami-labs/sealed-secrets. In fact, it allows you to encrypt your Secret into a SealedSecret, which is safe to store - even to a public repository. The SealedSecret can be decrypted only by the controller running in the target cluster and nobody else (not even the original author) is able to obtain the original Secret from the SealedSecret.

Install ```kubeseal``` command line tool:
```
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.16.0/kubeseal-linux-amd64 -O kubeseal
sudo install -m 755 kubeseal /usr/local/bin/kubeseal
```
Install Sealed Secrets controller:
```
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets-controller sealed-secrets/sealed-secrets -n kube-system
```
Once installed, Sealed Secrets colud be used in our use case to safely store in a public repository the secrets containing httpgo secrets. In fact, if we plan to share to push the secret into a public repo, instead of directly creating the secret via ```kubectl create secret tls my-tls-secret --key ca.key --cert ca.crt```, we need to create and deploy a SealedSecret. More specifically:
```
kubectl create secret tls my-tls-secret -o json >tlssecret.json --key ca.key --cert ca.crt --dry-run=client
```
```tlssecret.json``` will look like this:
```
{
    "kind": "Secret",
    "apiVersion": "v1",
    "metadata": {
        "name": "my-tls-secret",
        "creationTimestamp": null
    },
    "data": {
        "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFekNDQWZ1Z0F3SUJBZ0lVZTRrRmF5aEg1QU1PaG5XcDJ5a3dsWGdmOFlRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0dURVhNQlVHQTFVRUF3d09lVzkxY21SdmJXRnBiaTVqYjIwd0hoY05NakV4TVRBeU1UVXdPREF6V2hjTgpNakl4TVRBeU1UVXdPREF6V2pBWk1SY3dGUVlEVlFRRERBNTViM1Z5Wkc5dFlXbHVMbU52YlRDQ0FTSXdEUVlKCktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUwxQzJ0YkZ5THlscXJxQWk5NFhRR2MyY1lJY1gxaDIKeHgxTDRnZjNjMVFzclNwOUpxNDJrYWZ6THZnc0dJcCtRVkFLZ2NGb04zek9wQVlKUVhDcmhKZG01QnlzSjJUZwpmYVU0LzJCY21DQnBkb1lURW9KaHo5Y0lZQlJMSms3K1p3L29kZEh0eHFvMmVXU05DdjY5cW81N2N2R28yQWxjCm80TXR0Y0lWM3BBTlFyQkJDSFEyTElHWWI2ZDlqMFFzMERpaDAyQ09rWkhQUnRXMTNIdExVNDRuZGVCYXFsRVEKdTRyMXJoeHAyNFgvYU4rc3lFa3ZiTlBJY3JiNW5TQUE0VDAxWHpwM3pmUEw3WEMvWDA4WkgrbzVCcThZL25SYQpLdjlPeWhLQTBCVXRXdHlLQUFyREpMNGFuSHc3SVg5VG1LeGN2MEp0OTJZWXdRRGo5SU55UllVQ0F3RUFBYU5UCk1GRXdIUVlEVlIwT0JCWUVGSUgzQXp3SGlDYmUrN2dlc25jWXJadjBSV0w4TUI4R0ExVWRJd1FZTUJhQUZJSDMKQXp3SGlDYmUrN2dlc25jWXJadjBSV0w4TUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTApCUUFEZ2dFQkFJWWxPYU1rbUNHZE9Ga2pxSWRId08vdTh6T2lMTy9na2xtNm9wajF2Sm53S1k5V1JiS3JWcWdlCkN4bWhhZFp5cXU1NnJsaG04ZlcrYjhDNkZsYnVraHQ1TDZqTytLcGRrTDVZdGhUS1pSQ0ZCMzlVWU9MTldKVUUKNXFrRCtqUUYvRzRWdXU2MmY5VUx6UTcvcmFmMUNNVnRrWkY4SEV6V0UyVTR2cmZ6bXBJRmJpQm9nL2plL1VsMwpzZktrOVZ2Zk9aZEtsQ0d3Z0Z3My9weTUzK084TXBBQzV3bDFMUUlrSzFZT3h1UUVOVTJBMlV6dWxKTm5pdENUCkVNY05selIyZnVZVXAzT2MyK3JTMVJNekQ2N1cwdEZRQ0Z2aVcrdjRETDI1UC94WExXMmMvMXpNTzJ4bzhtaloKNmI2eGdScVg5QkRvOUlOSGhjeUhMZ1cwZmdld2daWT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        "tls.key": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdlVMYTFzWEl2S1dxdW9DTDNoZEFaelp4Z2h4ZldIYkhIVXZpQi9kelZDeXRLbjBtCnJqYVJwL011K0N3WWluNUJVQXFCd1dnM2ZNNmtCZ2xCY0t1RWwyYmtIS3duWk9COXBUai9ZRnlZSUdsMmhoTVMKZ21IUDF3aGdGRXNtVHY1bkQraDEwZTNHcWpaNVpJMEsvcjJxam50eThhallDVnlqZ3kyMXdoWGVrQTFDc0VFSQpkRFlzZ1podnAzMlBSQ3pRT0tIVFlJNlJrYzlHMWJYY2UwdFRqaWQxNEZxcVVSQzdpdld1SEduYmhmOW8zNnpJClNTOXMwOGh5dHZtZElBRGhQVFZmT25mTjg4dnRjTDlmVHhrZjZqa0dyeGorZEZvcS8wN0tFb0RRRlMxYTNJb0EKQ3NNa3ZocWNmRHNoZjFPWXJGeS9RbTMzWmhqQkFPUDBnM0pGaFFJREFRQUJBb0lCQUJCcUgvaklwcVJWNmZ6Swo4VmFOeGJRdDhLSk1PNmk4aElCeCtHU2dmWXdyWThsdm1VODZ4RjlBcEM0NkJOYmVKR1FBeFVnMDlic0pZUWgwCi9RdjhsRDlkV1NOemV1Y3c0VFRYUUs3bTJQcldxc1R1R29qY1d0NVhoNTI2OXRPYkZPMDRTQit3ODY0SGszZTUKRTk4TUxDSzNhanl6WENsVHM0ckpDQjZSTHdCblA5STJWUUNvN0tZVnZVME5yd1UxN1ErRXI1ZUxLQWtUSXg3bQpUQnBVV2lLb3BhZkU1ZG1NNk9oRWR4eTlFZmxFSDFaQ3l2UTBWSEVTbVkrVEFqR2JMVmNNbzhrOGRUZkpQenZsClVWYWVRL2h3LzRiS3NUTXhuRktOWWhSRjhFTzVuUXlMZTU4TjU0SzZ3cU55eW9DN1VVYTlqOWNuTTVBaXBoY3cKUEt4Z2JQRUNnWUVBNHhFdzY1L2tJQjBBZGtUQUplR0Y4RVpncytiN1VRRlR3akJsVXUwT1hKU2YvNzl4b0w2cApSVnpSVXVhL0NpZFBUSkZYeXBobUlodDVoY1BHNFZHMEswaXlIZ2d2QTg3elo2UHlqb3JBcnhSMGFzWG1FdkZpCm1Bb0xaYm1qVzFNTDJKZHplS3FtSUhvc2lVUklsT1FLdGtZSTVIYW1qelFOY016ZGx2UXBmRGNDZ1lFQTFXQnoKeGdwSHVIeEVPdFlWcnlleTE4WTN5NE11Qmk4T1ZlVFlhMExwdGxmOE1BZVMyYmg1QVpFcVZFODlzN2doWnBwQwo2N2hpa3hRNi9XMGpLU0hVYWpDWVlwN29IYm1LNjRrM2wzc0tVUytmSTJXV0FXZlJPUTJ2L3pTbk5JeGNORmlGClVRalpoZkxDRGtGQVNjcG5QWGNpWUVJdkRjbWlpd2YyVm9HTEJpTUNnWUVBM1lDNG96SC9mT0F0d2pHQTY3TWIKVUcrbkIvZ01NMUpESGN6T0d0NExRMzdzc2JSVXFRVTA1T2dOZm54LzRlekU2NkZnN2M1SzIzekh5QmhhV3hTegoyQUY3VjlhTjNuNDBiV2ErU0JUTXNENFk3c3VNaS9BVFNOT0xtTGxGeE9HM1RaczRWbjdKdmliUWFUdEdQcEJTCmJzclZBK0ZHeTYxd2F4ZytGWEtyUVhNQ2dZQUJFdzFDTUFjUWJML0ROQlREM3dWTmhOZi9GRmdFKy9Pc2h3eDMKN2N4VGVMbnlXL2RuVlVCMnU0NWxBa2tqUUlnYWhpaFVHNGVUaWdTS0JpU3BMbHh0ZEhVditmRGRSWFBubjdkQgo4Z0twU2Y0WkpZZk4xZ0g5c1kzelVRYU9neTVyclE1dXpBYWNZQTZPRjlJRkRSbmIrMStXOEg1Z0tXWENJWFlpCkZXRG4xUUtCZ0FSc0hqRVo1bmxYdlBuVmZxQVpheW9TRVEwY1llZTM1T2pRTndGZE9KTTY5bEYvUkIxelJVN0sKbjRwU3FYUjIrQmtOR3UraVJ3azFSVnNRdHJVTGJldHRtNmtLcXJxc2wyUmFoc0Y3SjRDbkczZUFmQjBRUGxxYgpKalBUWEw2SzNEQ1pIdmNxc0ZTeGlrOUE3R2lBdG5zZkFmREtnZWRmWFVRb0d3ZW50UUZxCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
    },
    "type": "kubernetes.io/tls"
}
```
and thus it is not safe to store this file in a public repo.
Let's seal it:
```
kubeseal <tlssecret.json >mysealedtlssecret.json
```
```mysealedtlssecret.json``` will look like:
```
{
  "kind": "SealedSecret",
  "apiVersion": "bitnami.com/v1alpha1",
  "metadata": {
    "name": "my-tls-secret",
    "namespace": "default",
    "creationTimestamp": null
  },
  "spec": {
    "template": {
      "metadata": {
        "name": "testsealedtls",
        "namespace": "default",
        "creationTimestamp": null
      },
      "type": "kubernetes.io/tls",
      "data": null
    },
    "encryptedData": {
      "tls.crt": "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",
      "tls.key": "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"
    }
  }
}
``` 
which is safe to be stored on a public repo.
Finally, the secret can be created using the sealed ```json``` file:
```
kubectl create -f mysealedtlssecret.json
```
```
kubectl get secret my-tls-secret
NAME            TYPE                DATA   AGE
my-tls-secret   kubernetes.io/tls   2      13m
```
## Open issues
- What is the best and most secure way for the plugin to authenticate with the Vault server (which should not be run in development mode)? In principle no credentials should be stored in the node, otherwise once the node is compromised, an hacker could get access to the vault server anyway. IAM roles?
