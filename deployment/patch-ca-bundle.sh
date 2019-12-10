#!/bin/bash

ROOT=$(cd $(dirname $0)/../../; pwd)

set -o errexit
set -o nounset
set -o pipefail

export CA_BUNDLE=$(kubectl get configmap -n kube-system extension-apiserver-authentication -o=jsonpath='{.data.client-ca-file}' | base64 | tr -d '\n')

cat <<EOF  >> ../k8s/validatingwebhook-ca-bundle.yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-bouncer-validate
webhooks:
- name: image-bouncer-validate.webhook.io
  rules:
    - operations: [ "CREATE" ]
      apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
  failurePolicy: Ignore
  clientConfig:
    service:
      name: image-bouncer
      namespace: default
      path: "/validate"
    caBundle: ${CA_BUNDLE}
EOF