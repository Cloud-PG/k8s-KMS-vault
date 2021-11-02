# k8s-KMS-vault
This repository contains code to deploy secret encryption at REST via a KMS system using a HashiCorp Vault deployment.
This implementation is based on https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/. KMS is based on envelop encryption mechanism.

In particular, you will be able to enable the encryption of secrets via KMS of TLS certificates which will be used by a simple httpgo server.
So, the key components of this deployments are:
- HashiCorp Vault deployment (https://www.vaultproject.io/)
- Vault plugin (https://github.com/ttedeschi/kubernetes-vault-kms-plugin)
- httpgo: a basic HTTP server written in Go language (https://github.com/vkuznet/httpgo)

## Quick start


## Components details
The full workflow is described in the diagram below, taken from [oracle](https://github.com/oracle/kubernetes-vault-kms-plugin)
![](vaultplugin.png)

### HashiCorp Vault
Vault is an identity-based secrets and encryption management system.

### Vault KMS plugin
The Kubernetes KMS Plugin Provider for HashiCorp Vault implementation is a simple adapter that adapts calls from Kubernetes to HashiCorp Vault APIs using configuration that determines how the plugin finds the HashiCorp Vault installation. The plugin is implemented based on the Kubernetes contract as described in Implementing a KMS plugin.

### Httpgo
HTTPGO is a basic HTTP server written in Go language


## Developer mode
Log into K8s master vm.
- Install and deploy Vault server in development mode
  ```
  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
  sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
  sudo apt-get update && sudo apt-get install vault
  vault server -dev 
  ```
- Deploy vaultPlugin
  ```
  git clone https://github.com/ttedeschi/kubernetes-vault-kms-plugin.git
  cd kubernetes-vault-kms-plugin/vault
  git mod init
  git test
  cd server
  go run grpcServer.go --vaultConfig config.json --socketFile test
  ```
  putting the right token inside ```config.json```
- Enable KMS encryption in Kubernetes:
  - ```git clone https://github.com/ttedeschi/k8s-KMS-vault.git```
  - modify ```/etc/kubernetes/manifests/kube-apiserver.yaml``` inserting:
    ```
    --encryption-provider-config=/opt/cloudadm/k8s-KMS-vault/encryptionConfiguration.yaml
    ...
    - mountPath: /opt/cloudadm
      name: cloudadm
      readOnly: true
    ...
    - hostPath:
      path: /opt/cloudadm
      type: DirectoryOrCreate
    name: cloudadm
    ```
    the api-server should be restarted automatically by kubelet
- Data is encrypted when written to etcd. After restarting your kube-apiserver, any newly created or updated secret should be encrypted when stored. To verify, you can use the etcdctl command line program to retrieve the contents of your secret:
  - ```vault secrets enable transit```
  - ```kubectl create secret generic secret1 -n default --from-literal=mykey=mydata```
  - ```ETCDCTL_API=3 etcdctl --endpoints=[192.168.0.8]:2379 --cert=/etc/kubernetes/pki/etcd/peer.crt  --key=/etc/kubernetes/pki/etcd/peer.key --cacert=/etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/default/secret1```
  - Verify the stored secret is prefixed with ```k8s:enc:kms:v1:``` which indicates the ```kms``` provider has encrypted the resulting data.
  - ``` kubectl get secret secret1 -o jsonpath='{.data}'``` should match ```mykey: bXlkYXRh```

### To debug
```cat /var/log/pods/kube-system_kube-apiserver-vnode-0.localdomain_ad7922ae75a63252aca31fd74e89087b/kube-apiserver/7.log```

### To test with certificate
``` 
openssl genrsa -out ca.key 2048
openssl req -x509   -new -nodes    -days 365   -key ca.key   -out ca.crt   -subj "/CN=yourdomain.com"
kubectl create secret tls my-tls-secret --key ca.key --cert ca.crt
```

