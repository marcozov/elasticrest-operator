/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	elasticsearchv1alpha1 "elasticrest-operator/api/v1alpha1"
)

// ILMPolicyReconciler reconciles a ILMPolicy object
type ILMPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type ElasticsearchClusterClient struct {
	ElasticsearchEndpoint string
	AuthorizationHeader   string
}

func (r *ILMPolicyReconciler) initElasticsearchClusterClient(ctx context.Context, policy *elasticsearchv1alpha1.ILMPolicy) (*ElasticsearchClusterClient, error) {
	endpoint, err := r.getElasticsearchEndpoint(policy)
	if err != nil {
		return nil, fmt.Errorf("Error while building the Elasticsearch endpoint: %w", err)
	}
	authorizationHeader, err := r.getElasticsearchAuthorizationHeader(ctx, policy)
	if err != nil {
		return nil, fmt.Errorf("Error while building the authorization header: %w", err)
	}

	client := &ElasticsearchClusterClient{
		ElasticsearchEndpoint: endpoint,
		AuthorizationHeader:   authorizationHeader,
	}

	return client, nil
}

func (r *ILMPolicyReconciler) getElasticsearchEndpoint(policy *elasticsearchv1alpha1.ILMPolicy) (string, error) {
	elasticsearchService := fmt.Sprintf("%s-es-http.%s.svc", policy.Spec.ElasticsearchCluster, policy.Namespace)

	return elasticsearchService, nil
}

func (r *ILMPolicyReconciler) getElasticsearchAuthorizationHeader(ctx context.Context, policy *elasticsearchv1alpha1.ILMPolicy) (string, error) {
	// The operator needs to be able to read and list secrets.
	elasticsearchCredentialsName := fmt.Sprintf("%s-es-elastic-user", policy.Spec.ElasticsearchCluster)

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: policy.Namespace,
		Name:      elasticsearchCredentialsName,
	}
	err := r.Get(ctx, secretKey, secret)
	if err != nil {
		return "", err
	}

	elasticUserPassword := secret.Data["elastic"]
	elasticUserPasswordEncoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", "elastic", elasticUserPassword)))

	return elasticUserPasswordEncoded, nil
}

func (r *ILMPolicyReconciler) getElasticsearchCertificateAuthority(ctx context.Context, policy *elasticsearchv1alpha1.ILMPolicy) (*x509.CertPool, error) {
	elasticsearchInternalCaName := fmt.Sprintf("%s-es-http-ca-internal", policy.Spec.ElasticsearchCluster)

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: policy.Namespace,
		Name:      elasticsearchInternalCaName,
	}
	err := r.Get(ctx, secretKey, secret)
	if err != nil {
		return nil, err
	}

	elasticsearchCaCert := secret.Data["tls.crt"]
	caCertPool := x509.NewCertPool()

	if ok := caCertPool.AppendCertsFromPEM(elasticsearchCaCert); !ok {
		err := fmt.Errorf("Could not create a CertPool from the elasticsearch certificate authority certificate.")
		return nil, err
	}

	return caCertPool, nil
}

//+kubebuilder:rbac:groups=elasticsearch.elasticrest.io,resources=ilmpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=elasticsearch.elasticrest.io,resources=ilmpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=elasticsearch.elasticrest.io,resources=ilmpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ILMPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *ILMPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// log := logf.Log.WithName("test")
	// log.V()
	// opts := zap.Options{Level: 1}
	// opts.

	log.Info("Entered reconcile loop")
	defer log.Info("Exit from reconcile loop")

	policy := &elasticsearchv1alpha1.ILMPolicy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		ignoreNotFound := client.IgnoreNotFound(err)
		if ignoreNotFound != nil {
			log.Error(err, "Unable to fetch the ILM Policy")
		}

		return ctrl.Result{}, ignoreNotFound
	}
	log.Info(fmt.Sprintf("ILM Policy %s/%s retrieved correctly", policy.Name, policy.Namespace))
	log.V(1).Info(fmt.Sprintf("Retrieved ILM Policy, %#v", policy))

	certPool, err := r.getElasticsearchCertificateAuthority(ctx, policy)
	if err != nil {
		status := &elasticsearchv1alpha1.ILMPolicyStatus{
			Description:  err.Error(),
			Method:       "N/A",
			ResponseCode: -1, // response code -1 means that the request failed
		}
		if err := r.updateStatus(ctx, policy, status, req); err != nil {
			log.Error(err, fmt.Sprintf("Could not update ILMPolicy status: %#v", status))
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	log.V(1).Info("Elasticsearch truststore retrieved and configured for the HTTP client")

	elasticsearchClient, err := r.initElasticsearchClusterClient(ctx, policy)
	if err != nil {
		log.Error(err, "Error while retrieving the elasticsearch client")
		return ctrl.Result{}, err
	}

	myFinalizerName := "elasticsearch.elasticrest.io/finalizer"
	// using finalizers https://book.kubebuilder.io/reference/using-finalizers.html
	if policy.ObjectMeta.DeletionTimestamp.IsZero() {
		if !containsString(policy.GetFinalizers(), myFinalizerName) {
			controllerutil.AddFinalizer(policy, myFinalizerName)
			if err != r.Update(ctx, policy) {
				return ctrl.Result{}, err
			}
		}
	} else {
		if containsString(policy.GetFinalizers(), myFinalizerName) {
			// try to delete the resource on the Elasticsearch backend
			// log.Info(fmt.Sprintf("Deleting the ILM policy: %#v", policy))
			log.Info(fmt.Sprintf("Deleting the ILM policy %s", fmt.Sprintf("%s/%s", policy.Name, policy.Namespace)))
			log.V(1).Info(fmt.Sprintf("Deleting the ILM policy %s: %#v", fmt.Sprintf("%s/%s", policy.Name, policy.Namespace), policy))
			if status, err := r.deleteExternalResources(ctx, httpClient, policy, elasticsearchClient); err != nil {
				log.Error(err, "Error while deleting external resources")

				// if the deletion of the resource (on the elasticsearch backend) fails, then proceed and remove the finalizer
				// More cases may be added here (e.g., the response code is 404)
				if status.ResponseCode == -1 && policy.Status.ResponseCode == -1 {
					log.Info("Trying to remove an ILMPolicy that could not be created. The ILMPolicy resource can be removed because it doesn't exist on the backend.")
				} else {
					// we may decide to not delete the resource on kubernetes if the Elasticsearch backend can't be properly cleaned up.
					// This behaviour may be changed.
					if err := r.updateStatus(ctx, policy, status, req); err != nil {
						log.Error(err, fmt.Sprintf("Could not update ILMPolicy status: %#v", status))
						return ctrl.Result{}, err
					}

					return ctrl.Result{}, err
				}
			}

			controllerutil.RemoveFinalizer(policy, myFinalizerName)
			if err := r.Update(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// log.Info(fmt.Sprintf("Creating/Updating the ILM policy: %#v", policy))
	log.Info(fmt.Sprintf("Creating/Updating the ILM policy %s", fmt.Sprintf("%s/%s", policy.Name, policy.Namespace)))
	log.V(1).Info(fmt.Sprintf("Creating/Updating the ILM policy %s: %#v", fmt.Sprintf("%s/%s", policy.Name, policy.Namespace), policy))
	status, err := r.addExternalResources(ctx, httpClient, policy, elasticsearchClient, req)
	if err := r.updateStatus(ctx, policy, status, req); err != nil {
		log.Error(err, fmt.Sprintf("Could not update ILMPolicy status: %#v", status))
		return ctrl.Result{}, err
	}

	if err != nil {
		log.Error(err, "Error when adding the external resource.")
		return ctrl.Result{}, err
	}

	log.Info("End of the reconcile loop")

	return ctrl.Result{}, nil
}

func (r *ILMPolicyReconciler) updateStatus(ctx context.Context, policy *elasticsearchv1alpha1.ILMPolicy, status *elasticsearchv1alpha1.ILMPolicyStatus, req ctrl.Request) error {
	log := logf.FromContext(ctx)

	log.Info(fmt.Sprintf("Updating ILMPolicy resource status with STATUS: %#v", status))
	policy.Status = *status
	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, fmt.Sprintf("Failed to update the ILMPolicy status. Desired state: %#v", status))
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ILMPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&elasticsearchv1alpha1.ILMPolicy{}).
		Complete(r)
}

func (r *ILMPolicyReconciler) addExternalResources(ctx context.Context, httpClient *http.Client, policy *elasticsearchv1alpha1.ILMPolicy, client *ElasticsearchClusterClient, req ctrl.Request) (*elasticsearchv1alpha1.ILMPolicyStatus, error) {
	// Add the external resources associated with the ILM Policy
	// PUT method is used and therefore this call can be used to update an existing resource.
	log := logf.FromContext(ctx)
	status := &elasticsearchv1alpha1.ILMPolicyStatus{
		Description:  "",
		Method:       http.MethodPut,
		ResponseCode: -1, // response code -1 means that the request failed
	}

	elasticsearchILMPolicyEndpoint := fmt.Sprintf("https://%s:9200/_ilm/policy", client.ElasticsearchEndpoint)
	log.Info(fmt.Sprintf("Elasticsearch ILM Policy endpoint: %s", elasticsearchILMPolicyEndpoint))

	// Create/update the ILM Policy. It's always a PUT request. No need to distinguish between adding a new ILM policy or updating an existing one.
	policyBody := policy.Spec.Body

	// check JSON for http methods https://riptutorial.com/go/example/27703/put-request-of-json-object
	// input validation
	policyRequest, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/%s", elasticsearchILMPolicyEndpoint, policy.Name), bytes.NewBufferString(policyBody))
	if err != nil {
		status.Description = err.Error()
		log.Error(err, "Error while creating the ILM policy create/update HTTP request")

		return status, err
	}

	policyRequest.Header.Set("Content-Type", "application/json")
	policyRequest.Header.Add("Authorization", fmt.Sprintf("Basic %s", client.AuthorizationHeader))

	resp, err := httpClient.Do(policyRequest)
	if err != nil {
		err := fmt.Errorf("Error while sending the HTTP creation/update request: %w", err)
		status.Description = err.Error()
		return status, err
	}
	status.ResponseCode = resp.StatusCode
	status.Description = resp.Status

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("Non-200 response code: %s", resp.Status))
		status.Description = err.Error()
		return status, err
	}

	return status, nil
}

func (r *ILMPolicyReconciler) deleteExternalResources(ctx context.Context, httpClient *http.Client, policy *elasticsearchv1alpha1.ILMPolicy, client *ElasticsearchClusterClient) (*elasticsearchv1alpha1.ILMPolicyStatus, error) {
	// Delete any external resources associated with the ILM Policy
	// Ensure that delete implementation is idempotent and safe to invoke
	// multiple times for same object.
	status := &elasticsearchv1alpha1.ILMPolicyStatus{
		Description:  "",
		Method:       http.MethodDelete,
		ResponseCode: -1, // response code -1 means that the request failed
	}

	elasticsearchILMPolicyEndpoint := fmt.Sprintf("https://%s:9200/_ilm/policy", client.ElasticsearchEndpoint)

	deleteRequest, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/%s", elasticsearchILMPolicyEndpoint, policy.Name), nil)
	if err != nil {
		err := fmt.Errorf("Error while creating the ILM policy HTTP deletion request: %w", err)
		status.Description = err.Error()
		return status, err
	}

	deleteRequest.Header.Add("Authorization", fmt.Sprintf("Basic %s", client.AuthorizationHeader))

	deleteResponse, err := httpClient.Do(deleteRequest)
	if err != nil {
		err := fmt.Errorf("Error while sending an HTTP deletion request: %w", err)
		status.Description = err.Error()
		return status, err
	}
	status.ResponseCode = deleteResponse.StatusCode
	status.Description = deleteResponse.Status

	if deleteResponse.StatusCode < 200 && deleteResponse.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("Non-200 response code: %s", deleteResponse.Status))
		status.Description = err.Error()

		return nil, err
	}

	return status, nil
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
