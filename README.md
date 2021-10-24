# k8s-KMS-vault
This repository contains code to deploy secret encryption at REST via a KMS system using a HashiCorp Vault deployment.
This implementation is based on https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/.

Three different components:
- HashiCorp Vault deployment (https://www.vaultproject.io/)
- Vault plugin (https://github.com/ttedeschi/kubernetes-vault-kms-plugin)
- httpgo: a basic HTTP server written in Go language (https://hub.docker.com/r/veknet/httpgo)

## HashiCorp Vault
```
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install consul hashicorp/consul --values helm-consul-values.yaml
helm install vault hashicorp/vault --values helm-vault-values.yaml
kubectl exec vault-0 -- vault operator init -key-shares=1 -key-threshold=1 -format=json > cluster-keys.json
VAULT_UNSEAL_KEY=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[]")
kubectl exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY
```

## Vault plugin
The Kubernetes KMS Plugin Provider for HashiCorp Vault implementation is a simple adapter that adapts calls from Kubernetes to HashiCorp Vault APIs using configuration that determines how the plugin finds the HashiCorp Vault installation.

```kubectl deploy plugin.yaml```

Edit the API server pod specification file ```/etc/kubernetes/manifests/kube-apiserver.yaml``` on the master node and set the ```--encryption-provider-config``` parameter to the path of that file: ```--encryption-provider-config=</path/to/EncryptionConfig/File>```

Then restart API server.

## Check encryption is OK
Data is encrypted when written to etcd. After restarting your kube-apiserver, any newly created or updated secret should be encrypted when stored. To verify, you can use the etcdctl command line program to retrieve the contents of your secret.

Create a new secret called secret1 in the default namespace:
```
kubectl create secret generic secret1 -n default --from-literal=mykey=mydata
```
Using the etcdctl command line, read that secret out of etcd:
```
ETCDCTL_API=3 etcdctl get /kubernetes.io/secrets/default/secret1 [...] | hexdump -C
```
where [...] must be the additional arguments for connecting to the etcd server.

Verify the stored secret is prefixed with k8s:enc:kms:v1:, which indicates that the kms provider has encrypted the resulting data.

Verify that the secret is correctly decrypted when retrieved via the API:
```
kubectl describe secret secret1 -n default
```
should match mykey: ```mydata```

