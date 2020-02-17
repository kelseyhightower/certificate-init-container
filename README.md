# Certificate Init Container

The `certificate-init-container` generates TLS certificates for pods using the [Kubernetes certificate API](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster).

See the [current release](#current-release) for usage details.

## Prerequisites

* Kubernetes 1.6.0+

## Usage

Create a deployment that uses the `certificate-init-container`:

```
kubectl create -f deployments/tls-app.yaml
```

The `certificate-init-container` will generate a private key, certificate signing request (csr), and submit a certificate signing request to the Kubernetes certificate API, then wait for the [certificate to be approved](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#approving-certificate-signing-requests).

```
kubectl get pods
```
```
NAME                       READY     STATUS     RESTARTS   AGE
tls-app-2342064067-c9xwf   0/1       Init:0/1   0          5s
```

View the `certificate-init-container` logs for more details:

```
kubectl logs tls-app-2342064067-c9xwf -c certificate-init-container
```
```
2017/04/06 06:58:02 wrote /etc/tls/tls.key
2017/04/06 06:58:02 wrote /etc/tls/tls.csr
2017/04/06 06:58:02 waiting for certificate...
2017/04/06 06:58:02 certificate signing request (tls-app-2342064067-c9xwf-default) not approved; trying again in 5 seconds
2017/04/06 06:58:27 certificate signing request (tls-app-2342064067-c9xwf-default) not approved; trying again in 5 seconds
```

List the certificate signing requests and locate the csr pending for the `tls-app` pod:

```
kubectl get csr
```
```
NAME                               AGE       REQUESTOR                               CONDITION
tls-app-2342064067-c9xwf-default   1m        system:serviceaccount:default:default   Pending
```

Review the csr details:

```
kubectl describe csr tls-app-2342064067-c9xwf-default
```

```
Name:                   tls-app-2342064067-c9xwf-default
Labels:                 <none>
Annotations:            <none>
CreationTimestamp:      Thu, 06 Apr 2017 06:17:16 -0700
Requesting User:        system:serviceaccount:default:default
Status:                 Pending
Subject:
        Common Name:    10-228-0-10.default.pod.cluster.local
        Serial Number:
Subject Alternative Names:
        DNS Names:      10-228-0-10.default.pod.cluster.local
                        example.com
                        tls-app.default.svc.cluster.local
        IP Addresses:   10.228.0.10
                        127.0.0.1
Events:	<none>
```

Approve the pending certificate signing request:

```
kubectl certificate approve tls-app-2342064067-c9xwf-default
```
```
certificatesigningrequest "tls-app-2342064067-c9xwf-default" approved
```

Once the certificate signing request has been approved the `certificate-init-container` will fetch the signed certificate and write it to a shared filesystem.

```
kubectl logs tls-app-2342064067-c9xwf -c certificate-init-container
```
```
2017/04/06 06:58:02 wrote /etc/tls/tls.key
2017/04/06 06:58:02 wrote /etc/tls/tls.csr
2017/04/06 06:58:02 waiting for certificate...
2017/04/06 06:58:02 certificate signing request (tls-app-2342064067-c9xwf-default) not approved; trying again in 5 seconds
2017/04/06 06:58:27 certificate signing request (tls-app-2342064067-c9xwf-default) not approved; trying again in 5 seconds
...
2017/04/06 07:00:28 wrote /etc/tls/tls.crt
```

Next the `certificate-init-container` will exit and the pod will start the remaining containers which will have access to the certificate and private key.

```
kubectl get pods
```
```
NAME                       READY     STATUS    RESTARTS   AGE
tls-app-2342064067-c9xwf   1/1       Running   0          2m
```

Create a service for the `tls-app` deployment to view the certificate details.

```
kubectl expose deployment tls-app --type=LoadBalancer
```

## Current Release

Container Image:

```
gcr.io/hightowerlabs/certificate-init-container:0.0.1
```

See the [example deployment](deployments/tls-app.yaml) for more details.

Usage:

```
certificate-init-container -h
```
```
Usage of certificate-init-container:
  -additional-dnsnames string
    	additional dns names; comma separated
  -cert-dir string
    	The directory where the TLS certs should be written (default "/etc/tls")
  -cluster-domain string
    	Kubernetes cluster domain (default "cluster.local")
  -hostname string
    	hostname as defined by pod.spec.hostname
  -namespace string
    	namespace as defined by pod.metadata.namespace (default "default")
  -pod-ip string
    	IP address as defined by pod.status.podIP
  -pod-name string
    	name as defined by pod.metadata.name
  -service-ips string
    	service IP addresses that resolve to this Pod; comma separated
  -service-names string
    	service names that resolve to this Pod; comma separated
  -subdomain string
    	subdomain as defined by pod.spec.subdomain
  -keysize int
        bit size of private key (default 2048)
```
