# VPN

Kilo enables peers outside of a Kubernetes cluster to connect to the created WireGuard network.
This enables several use cases, for example:
* giving cluster applications secure access to external services, e.g. services behind a corporate VPN;
* allowing external services to access the cluster; and
* enabling developers and support to securely debug cluster resources.

In order to declare a peer, start by defining a Kilo Peer resource.
See the following `peer.yaml`, where the `publicKey` field holds a [generated WireGuard public key](https://www.wireguard.com/quickstart/#key-generation):

```yaml
apiVersion: kilo.squat.ai/v1alpha1
kind: Peer
metadata:
  name: squat
spec:
  allowedIPs:
  - 10.5.0.1/32 # Example IP address on the peer's interface.
  publicKey: GY5aT1N9dTR/nJnT1N2f4ClZWVj0jOAld0r8ysWLyjg=
  persistentKeepalive: 10
```

Then, apply the resource to the cluster:

```shell
kubectl apply -f peer.yaml
```

Now, the `kgctl` tool can be used to generate the WireGuard configuration for the newly defined peer:

```shell
PEER=squat
kgctl showconf peer $PEER
```

This will produce some output like:

```ini
[Peer]
PublicKey = 2/xU029dz/WtvMZAbnSzmhicl8U1/Y3NYmunRr8EJ0Q=
AllowedIPs = 10.4.0.2/32, 10.2.3.0/24, 10.1.0.3/32
Endpoint = 108.61.142.123:51820
```

The configuration can then be applied to a local WireGuard interface, e.g. `wg0`:

```shell
IFACE=wg0
kgctl showconf peer $PEER > peer.ini
sudo wg setconf $IFACE peer.ini
```

Finally, in order to access the cluster, the client will need appropriate routes for the new configuration.
For example, on a Linux machine, the creation of these routes could be automated by running:

```shell
for ip in $(kgctl showconf peer $PEER | grep AllowedIPs | cut -f 3- -d ' ' | tr -d ','); do
	sudo ip route add $ip dev $IFACE
done
```

When using the official Mac OS WireGuard client, the routes from `AllowedIPs` will be automatically
routed to the VPN tunnel. You do not need to manually register routes there.

Once the routes are in place, the connection to the cluster can be tested.
For example, try connecting to the API server:

```shell
curl -k https://10.0.27.179:6443
```

Likewise, the cluster now also has layer 3 access to the newly added peer.
From any node or Pod on the cluster, one can now ping the peer:

```shell
ping 10.5.0.1
```

If the peer exposes a layer 4 service, for example an HTTP service, then one could also make requests against that endpoint from the cluster:

```shell
curl http://10.5.0.1
```

Kubernetes Services can be created to provide better discoverability to cluster workloads for services exposed by peers, for example:

```shell
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: important-service
spec:
  ports:
    - port: 80
---
apiVersion: v1
kind: Endpoints
metadata:
    name: important-service
subsets:
  - addresses:
      - ip: 10.5.0.1
    ports:
      - port: 80
EOF
```

[See the multi-cluster services docs for more details on connecting clusters to external services](./multi-cluster-services.md).

## Accessing Service IPs via the VPN

Service IPs are usually assigned to a separate IP address range compared to the Pod IPs. Kilo will only
output the Pod IP range in the WireGuard Client configuration when running `kgctl showconf peer`. This is
because Service IPs can be sent to any Kubernetes node, and then routing happens internally towards
the pods.

To access service IPs via the VPN client, simply add them in your WireGuard client configuration
to the `AllowedIPs` list, f.e. like `10.43.0.0/15` (if your services are allocated from the `10.43` IP
range).

## Using Kilo only as VPN server

You can also use Kilo only for accessing your cluster pods and services via VPN client; and not as
CNI Plugin.

This is documented [in the docs for vpn-only](./vpn-only.md), because this is easier to configure
and deploy.