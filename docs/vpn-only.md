# Kilo as VPN Server to connect into the cluster

Use Case: Connect into the Kubernetes Cluster via WireGuard VPN, so that a WireGuard client has direct
access to Pods and Services.

## Prerequisites

- Ensure Wireguard is installed on the host system
- UDP port 51820 must be externally reachable to the cluster

## Deployment

- For this case, it is enough to deploy a single instance of Kilo into the cluster. Kilo should be
  **pinned** to a single Node, because the WireGuard private key is host-specific.
- CNI has to be disabled, because you are keeping the existing CNI plugin.
- You can use in-cluster Kubernetes configuration, and do not need to mount the host Kubernetes config.
  (The latter is only needed to extract in the CNI case to detect the outside-visible Hostname for
  each node).
- We only tested this with Flannel or Flannel+Calico (=Canal) so far.

You can still access all Kubernetes Services and Pods, no matter where they run, in this configuration.

The full configuration can be found at [manifests/kilo-vpn-only-example.yaml](../manifests/kilo-vpn-only-example.yaml).

**Make sure to adjust the `nodeSelector` in the `DaemonSet`**.

## Registering a new VPN client

1. Create a new WireGuard keypair on the VPN Client. Remember the public key.

2. For the client, create a Kubernetes `peer` resource:

   - pick a new, unique, IP address for the client from the `10.5.0.*` IP range.
     Based on this IP, we can lateron decide what the client can access.

   - add the public key from the VPN client (see step 1) to the `peer` resource.

   Example:

   ```
   apiVersion: kilo.squat.ai/v1alpha1
   kind: Peer
   metadata:
     name: squat
   spec:
     allowedIPs:
     # desired IP address of the client's interface.
     - 10.5.0.1/32
     # Public Key of the client
     publicKey: A......................................=
     persistentKeepalive: 10
   ```

3. Configure your local VPN client in the following way:

   ```ini
   [Interface]
   PrivateKey = (already filled)
   # IP address of VPN client; from the "peer" kubernetes resource as configured above
   Address = 10.5.0.1/32

   [Peer]
   # from within the "kilo" Pod, run "wg" - that outputs the persistent, public key for
   # the server
   PublicKey = B......................................=

   # Add the Pod and Service networks, e.g. if 10.42.* is the Pod Network; and 10.43.*
   # is the Service network:
   AllowedIPs = 10.42.0.0/16, 10.43.0.0/16

   # public IP address of the Kilo node + Wireguard/Kilo UDP Port
   Endpoint = 138.201.76.122:51820

   # the server is always reachable, so we do not need PersistentKeepalive in
   # this direction.
   PersistentKeepalive = 0
   ```

## Optional: Using Calico / Canal to restrict the NetworkPolicy in the Cluster

If you are running Calico + Flannel (=Canal), you can use `HostEndpoint` combined
with a `GlobalNetworkPolicy` to restrict what each VPN client can access in the cluster:

```yaml
---
apiVersion: crd.projectcalico.org/v1
kind: HostEndpoint
metadata:
  name: wireguard-kilo
  labels:
    interface: wireguard-kilo
spec:
  node: THE_KILO_NODE_HERE
  expectedIPs:
  # in the "kilo" container, we run "ip address show kilo0",
  # and this is the IP of the "inner" side of the wireguard interface.
  # thus, we need to match on this IP here.
  - 10.4.0.1

---
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: wireguard-kilo
spec:
  selector: interface == 'wireguard-kilo'
  # we want to apply the policy as it enters our cluster (exits the wireguard
  # interface). On the application pods, we could not apply it anymore, because
  # the IP address gets rewritten to the Flannel interface IP.
  applyOnForward: true
  types:
  - Ingress
  ingress:
    - action: Allow
      source:
        nets:
          - 10.5.0.1/32 # a certain VPN client ...
      destination:
        # ... can access a certain app
        namespaceSelector: network-policy-namespace == "cattle-prometheus"
        selector: app == "grafana"

    # anything which is not whitelisted explicitly is forbidden
    - action: Deny
```