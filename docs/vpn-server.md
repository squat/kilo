# VPN Server

The cluster VPN created by Kilo can also be used by peers as a gateway to access the Internet.
In order configure a local machine to use the cluster VPN as a gateway to the Internet, first register the local machine as a peer of the cluster following the steps in the [VPN docs](./vpn.md).

Once the machine is registered, generate the configuration for the local peer:

```shell
PEER=squat # name of the registered peer
kgctl showconf peer $PEER > peer.ini
```

Next, the WireGuard configuration must be modified to enable routing traffic for any IP via a node in the cluster.
To do so, open the WireGuard configuration in an editor, select a node in the cluster, and set the `AllowedIPs` field of that node's corresponding `peer` section to `0.0.0.0/0, ::/0`:

```shell
$EDITOR peer.ini
```

The configuration should now look something like:

```ini
[Peer]
PublicKey = 2/xU029dz/WtvMZAbnSzmhicl8U1/Y3NYmunRr8EJ0Q=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 108.61.142.123:51820
```

The configuration can then be applied to the local WireGuard interface, e.g. `wg0`:

```shell
IFACE=wg0
sudo wg setconf $IFACE peer.ini
```

Next, add routes for the public IPs of the WireGuard peers to ensure that the packets encapsulated by WireGuard are sent through a real interface:

```shell
default=$(ip route list all | grep default | awk '{$1=""; print $0}')
for ip in $(sudo wg | grep endpoint | awk '{print $2}' | sed 's/\(.\+\):[0-9]\+/\1/'); do
    sudo ip route add $ip $default
done
```

Finally, the local machine can be configured to use the WireGuard interface as the device for the default route:

```shell
sudo ip route delete default
sudo ip route add default dev $IFACE
```

The local machine is now using the selected node as its Internet gateway and the connection can be verified.
For example, try finding the local machine's external IP address:
```shell
curl https://icanhazip.com
```
