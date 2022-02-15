# ElasticREST Operator
An operator for Elasticsearch REST API.

# How-to
operator-sdk init --domain elasticrest.io
operator-sdk create api --group elasticsearch --version v1alpha1 --kind ILMPolicy --resource --controller
operator-sdk create api --group elasticsearch --version v1alpha1 --kind IndexTemplate --resource --controller

# Ideas
Implementation of resource creation/update: keep a state of the resource (in k8s), based on the rest api call sent to the elasticsearch backend.
Do the same for deletions. The resource should keep the state of what's going on.

Deletion should always be possible: what if there are errors when deleting the resource? Should we distinguish between a resource that successfully triggered
the reesource creation in the backend, from one that failed? Should we just allow deletion (when errors occur) in the second case?

Unmanaged resources are assumed to be present when required. --> from https://www.stephenzoio.com/kubernetes-operators-for-resource-management/
We could assume that Elasticsearch is such unmanaged resource and therefore we assume that it's present --> if it's not, it's a failure state (instead of missing dependency).

Useful reading: https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile .

Check https://github.com/kubernetes-sigs/controller-runtime/blob/v0.10.0/pkg/reconcile/reconcile.go for the reconcile interface

Relevant as well: https://sdk.operatorframework.io/docs/building-operators/golang/advanced-topics/ .

Best practices: https://sdk.operatorframework.io/docs/best-practices/best-practices/ .

This is how I found out the mistake when introducing the status: https://book-v1.book.kubebuilder.io/basics/status_subresource.html .

More API concepts (e.g., generated values):
 - https://kubernetes.io/docs/reference/using-api/api-concepts/ .
 - https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#status-subresource

Sample of github issues with similar problem for status update:
 - https://github.com/andreaskaris/sosreport-operator/commit/f2c9b6c4833c6ed005e18131d9c6ba77ff0aba6e
 - https://github.com/carlosedp/lbconfig-operator/commit/49b76326f7f1884616f2d840e3a5d6dd8c4c25ca
 - https://docs.armory.io/armory-enterprise/installation/armory-operator/op-troubleshooting/
 - https://github.com/kubernetes/kubernetes/issues/28149
 - https://github.com/operator-framework/operator-sdk/issues/981

operator sdk reference:
 - https://github.com/operator-framework/operator-sdk/blob/v1.15.0/website/content/en/docs/building-operators/golang/references/client.md#update

another sample code for the status update:
 - https://stackoverflow.com/questions/65120965/operator-sdk-controller-failed-to-update-custom-resource-status
 - https://github.com/operator-framework/operator-sdk/blob/latest/testdata/go/v3/memcached-operator/controllers/memcached_controller.go
