# Peer Validation

A [ValidatingAdmissionWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook) can  be used to avoid applying faulty Peer configurations to the cluster.

## How It Works

A [ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#configure-admission-webhooks-on-the-fly) is a Kubernetes resource that can be used to dynamically specify a service (i.e. the webhook server) that should validate operations (e.g. `UPDATE`, `CREATE`, etc.) on a particular resource (e.g. Kilo Peers).
Once such a configuration is applied, the Kubernetes API server will send an AdmissionReviewRequest to the webhook service every time the specified operations are applied to the resource of the specified type.
With regard to the [failure policy](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy), the API server will apply the requested changes to a resource if the request was answered with `"allowed": true`, or deny the changes if the answer was `"allowed": false`.

In case of Kilo Peer Validation, the specified operations are `UPDATE` and `CREATE`, the resources are `Peers`, and the default `failurePolicy` is set to `Fail`.
View the full ValidatingWebhookConfiguration [here](https://github.com/squat/kilo/blob/main/manifests/peer-validation.yaml).

## Getting Started

Apply the Service, the Deployment of the actual webserver, and the ValidatingWebhookConfiguration with:
```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/blob/main/manifests/peer-validation.yaml
```

The Kubernetes API server will only talk to webhook servers via TLS so the Kilo-Peer-Validation server must be given a valid TLS certificate and key, and the API server must be told what certificate authority (CA) to trust.
The above manifest will use [kube-webhook-certgen](https://github.com/jet/kube-webhook-certgen) to generate the requiered certificates and patch the [ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#configure-admission-webhooks-on-the-fly).
