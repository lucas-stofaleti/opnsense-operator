/*
Copyright 2026.

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

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
	"github.com/lucas-stofaleti/opnsense-operator/internal/opnsense"
)

// OPNsenseConnectionReconciler reconciles a OPNsenseConnection object
type OPNsenseConnectionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=opnsenseconnections,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=opnsenseconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=opnsenseconnections/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *OPNsenseConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	conn := &firewallv1alpha1.OPNsenseConnection{}
	if err := r.Get(ctx, req.NamespacedName, conn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fetch the Secret that holds the OPNsense API credentials.
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      conn.Spec.Credentials.SecretRef.Name,
		Namespace: conn.Spec.Credentials.SecretRef.Namespace,
	}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Credentials Secret not found", "secret", secretKey)
			return r.setReadyFailed(ctx, conn, "SecretNotFound",
				fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name),
				err)
		}
		return ctrl.Result{}, fmt.Errorf("fetch credentials Secret %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}

	// Extract credentials. Both keys must be present and non-empty.
	apiKey := string(secret.Data["apiKey"])
	apiSecret := string(secret.Data["apiSecret"])
	if apiKey == "" || apiSecret == "" {
		log.Info("Credentials Secret is missing required keys", "secret", secretKey)
		return r.setReadyFailed(ctx, conn, "InvalidCredentials",
			fmt.Sprintf("Secret %s/%s must have non-empty keys 'apiKey' and 'apiSecret'", secretKey.Namespace, secretKey.Name),
			fmt.Errorf("Secret %s/%s is missing required credential keys", secretKey.Namespace, secretKey.Name))
	}

	// Build the HTTP client, optionally applying TLS configuration from the spec.
	httpClient, err := r.buildHTTPClient(ctx, conn.Spec.TLS)
	if err != nil {
		return r.setReadyFailed(ctx, conn, "ConnectionFailed",
			fmt.Sprintf("Could not configure TLS for OPNsense at %s: %s", conn.Spec.URL, err),
			err)
	}

	// Perform a lightweight connectivity and authentication check against OPNsense.
	opnsenseClient := opnsense.NewClient(conn.Spec.URL, apiKey, apiSecret, httpClient)
	if err := opnsenseClient.CheckConnectivity(ctx); err != nil {
		log.Info("Connectivity check failed", "url", conn.Spec.URL, "error", err)
		return r.setReadyFailed(ctx, conn, "ConnectionFailed",
			fmt.Sprintf("Could not connect to OPNsense at %s: %s", conn.Spec.URL, err),
			err)
	}

	log.Info("Connectivity check succeeded", "url", conn.Spec.URL)
	return ctrl.Result{RequeueAfter: 1 * time.Minute}, r.setReadyCondition(ctx, conn, metav1.ConditionTrue, "ConnectionVerified",
		fmt.Sprintf("Successfully connected to OPNsense at %s", conn.Spec.URL))
}

// setReadyFailed sets Ready=False on the OPNsenseConnection status and returns the given cause error
// so controller-runtime will requeue the request.
func (r *OPNsenseConnectionReconciler) setReadyFailed(ctx context.Context, conn *firewallv1alpha1.OPNsenseConnection, reason, message string, cause error) (ctrl.Result, error) {
	if err := r.setReadyCondition(ctx, conn, metav1.ConditionFalse, reason, message); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// setReadyCondition updates the Ready status condition on the OPNsenseConnection.
func (r *OPNsenseConnectionReconciler) setReadyCondition(ctx context.Context, conn *firewallv1alpha1.OPNsenseConnection, status metav1.ConditionStatus, reason, message string) error {
	meta.SetStatusCondition(&conn.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: conn.Generation,
	})
	if err := r.Status().Update(ctx, conn); err != nil {
		return fmt.Errorf("update OPNsenseConnection status: %w", err)
	}
	return nil
}

// buildHTTPClient constructs an *http.Client with TLS settings derived from the spec.
// Returns nil when no custom TLS is needed, which causes opnsense.NewClient to use http.DefaultClient.
func (r *OPNsenseConnectionReconciler) buildHTTPClient(ctx context.Context, tlsSpec *firewallv1alpha1.TLSSpec) (*http.Client, error) {
	if tlsSpec == nil {
		return nil, nil
	}

	// A custom CA takes precedence over insecureSkipVerify.
	if tlsSpec.CASecretRef != nil {
		caKey := types.NamespacedName{
			Name:      tlsSpec.CASecretRef.Name,
			Namespace: tlsSpec.CASecretRef.Namespace,
		}
		caSecret := &corev1.Secret{}
		if err := r.Get(ctx, caKey, caSecret); err != nil {
			return nil, fmt.Errorf("fetch CA Secret %s/%s: %w", caKey.Namespace, caKey.Name, err)
		}
		caCert, ok := caSecret.Data["ca.crt"]
		if !ok || len(caCert) == 0 {
			return nil, fmt.Errorf("CA Secret %s/%s must have a non-empty key 'ca.crt'", caKey.Namespace, caKey.Name)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from Secret %s/%s", caKey.Namespace, caKey.Name)
		}
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}, nil
	}

	if tlsSpec.InsecureSkipVerify {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}, nil
	}

	return nil, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OPNsenseConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1alpha1.OPNsenseConnection{}).
		Named("opnsenseconnection").
		Complete(r)
}
