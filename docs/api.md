# API
This document is a reference of the API types introduced by Kilo.

> Note this document is generated from code comments. When contributing a change to this document, please do so by changing the code comments.

## Table of Contents
* [DNSOrIP](#dnsorip)
* [Peer](#peer)
* [PeerEndpoint](#peerendpoint)
* [PeerList](#peerlist)
* [PeerSpec](#peerspec)

## DNSOrIP

DNSOrIP represents either a DNS name or an IP address. IPs, as they are more specific, are preferred.

| Field | Description | Scheme | Required |
| ----- | ----------- | ------ | -------- |
| dns | DNS must be a valid RFC 1123 subdomain. | string | false |
| ip | IP must be a valid IP address. | string | false |

[Back to TOC](#table-of-contents)

## Peer

Peer is a WireGuard peer that should have access to the VPN.

| Field | Description | Scheme | Required |
| ----- | ----------- | ------ | -------- |
| metadata | Standard object’s metadata. More info: https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#metadata | [metav1.ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#objectmeta-v1-meta) | false |
| spec | Specification of the desired behavior of the Kilo Peer. More info: https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#spec-and-status | [PeerSpec](#peerspec) | true |

[Back to TOC](#table-of-contents)

## PeerEndpoint

PeerEndpoint represents a WireGuard enpoint, which is a ip:port tuple.

| Field | Description | Scheme | Required |
| ----- | ----------- | ------ | -------- |
| dnsOrIP | DNSOrIP is a DNS name or an IP address. | [DNSOrIP](#dnsorip) | true |
| port | Port must be a valid port number. | uint32 | true |

[Back to TOC](#table-of-contents)

## PeerList

PeerList is a list of peers.

| Field | Description | Scheme | Required |
| ----- | ----------- | ------ | -------- |
| metadata | Standard list metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds | [metav1.ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#listmeta-v1-meta) | false |
| items | List of peers. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md | [][Peer](#peer) | true |

[Back to TOC](#table-of-contents)

## PeerSpec

PeerSpec is the description and configuration of a peer.

| Field | Description | Scheme | Required |
| ----- | ----------- | ------ | -------- |
| allowedIPs | AllowedIPs is the list of IP addresses that are allowed for the given peer's tunnel. | []string | true |
| endpoint | Endpoint is the initial endpoint for connections to the peer. | *[PeerEndpoint](#peerendpoint) | false |
| persistentKeepalive | PersistentKeepalive is the interval in seconds of the emission of keepalive packets by the peer. This defaults to 0, which disables the feature. | int | false |
| presharedKey | PresharedKey is the optional symmetric encryption key for the peer. | string | true |
| publicKey | PublicKey is the WireGuard public key for the peer. | string | true |

[Back to TOC](#table-of-contents)
