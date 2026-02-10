# Network Policies

Network policies allow specifying whether and how different groups of Pods running in a Kubernetes cluster can communicate with one another.
In other words, they can be used to control and limit the ingress and egress traffic to and from Pods.
Naturally, network policies can be used to restrict which WireGuard peers have access to which Pods and vice-versa.
Support for [Kubernetes network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) can be easily added to any cluster running Kilo by deploying a utility such as [kube-router](https://github.com/cloudnativelabs/kube-router).

## Installation

The following command adds network policy support by deploying kube-router to work alongside Kilo:

```shell
kubectl apply -f https://raw.githubusercontent.com/cozystack/kilo/main/manifests/kube-router.yaml
```

## Examples

Network policies could now be deployed to the cluster.
Consider the following example scenarios.

### Deny All Ingress Except WireGuard

Imagine that an organization wants to limit access to a namespace to only allow traffic from the WireGuard VPN.
Access to a namespace could be limited to only accept ingress from a CIDR range with:

```shell
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-ingress-except-wireguard
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.5.0.0/16 # The WireGuard mesh/s CIDR.
EOF
```

### Deny Egress to WireGuard Peers

Consider the case where Pods running in one namespace should not have access to resources in the WireGuard mesh, e.g. because the Pods are potentially untrusted.
In this scenario, a policy to restrict access to the WireGuard peers could be created with:

```shell
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-to-wireguard
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.5.0.0/16 # The WireGuard mesh's CIDR.
EOF
```
