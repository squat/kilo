# Peer Validation

A [ValidatingAdmissionWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook) can  be used to avoid applying faulty Peer configurations to the cluster.

## How It Works

A [ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#configure-admission-webhooks-on-the-fly) is a Kubernetes resource that can be used to dynamically specify a service (i.e. the webhook server) that should validate operations (e.g. `UPDATE`, `CREATE`, etc.) on a particular resource (e.g. Kilo Peers).
Once such a configuration is applied, the Kubernetes API server will send an AdmissionReviewRequest to the webhook service every time the specified operations are applied to the resource of the specified type.
With regard to the [failure policy](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy), the API server will apply the requested changes to a resource if the request was answered with `"allowed": true`, or deny the changes if the answer was `"allowed": false`.

In case of Kilo Peer Validation, the specified operations are `UPDATE` and `CREATE`, the resources are `Peers`, and the default `failurePolicy` is set to `Fail`.
View the full ValidatingWebhookConfiguration [here](https://github.com/leonnicolas/kilo-peer-validation/blob/main/deployment-no-cabundle.yaml).

## Getting Started

[Kilo-Peer-Validation](https://github.com/leonnicolas/kilo-peer-validation) is a webserver that rejects any AdmissionReviewRequest with a faulty Peer configuration.

Apply the Service, the Deployment of the actual webserver, and the ValidatingWebhookConfiguration with:
```shell
kubectl apply -f https://raw.githubusercontent.com/leonnicolas/kilo-peer-validation/main/deployment-no-cabundle.yaml
```

The Kubernetes API server will only talk to webhook servers via TLS so the Kilo-Peer-Validation server must be given a valid TLS certificate and key, and the API server must be told what certificate authority (CA) to trust.
One way to do this is to use the [kube-webhook-certgen](https://github.com/jet/kube-webhook-certgen) project to create a Kubernetes Secret holding the TLS certificate and key for the webhook server and to make a certificate signing request to the Kubernetes API server.
The following snippet can be used to run kube-webhook-certgen in a Docker container to create a Secret and certificate signing request:
```shell
docker run -v /path/to/kubeconfig:/kubeconfig.yaml:ro jettech/kube-webhook-certgen:v1.5.2 --kubeconfig /kubeconfig.yaml create --namespace kilo --secret-name peer-validation-webhook-tls --host peer-validation,peer-validation.kilo.svc --key-name tls.key --cert-name tls.config
```

Now, the Kubernetes API server can be told what CA to trust by patching the ValidatingWebhookConfiguration with the newly created CA bundle:
```shell
docker run -v /path/to/kubeconfig:/kubeconfig.yaml:ro jettech/kube-webhook-certgen:v1.5.2 --kubeconfig /kubeconfig.yaml patch --webhook-name peer-validation.kilo.svc --secret-name peer-validation-webhook-tls --namespace kilo --patch-mutating=false
```

## Alternative Method

An alternative method to generate a ValidatingWebhookConfiguration manifest without using Kubernetes' Certificate Signing API is described in [Kilo-Peer-Validation](https://github.com/leonnicolas/kilo-peer-validation#use-the-set-up-script).
