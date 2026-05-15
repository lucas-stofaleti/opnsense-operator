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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
	"github.com/lucas-stofaleti/opnsense-operator/internal/opnsense"
)

const aliasFinalizer = "firewall.opnsense.io/finalizer"

// AliasReconciler reconciles a Alias object
type AliasReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=aliases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=aliases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=aliases/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Alias object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *AliasReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	alias := &firewallv1alpha1.Alias{}
	if err := r.Get(ctx, req.NamespacedName, alias); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling Alias", "name", alias.Name, "namespace", alias.Namespace)

	if !alias.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(alias, aliasFinalizer) {
			return ctrl.Result{}, nil
		}

		if alias.Status.UUID == "" {
			log.Info("Removing finalizer for Alias with no external resource")
			controllerutil.RemoveFinalizer(alias, aliasFinalizer)
			if err := r.Update(ctx, alias); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
			}
			return ctrl.Result{}, nil
		}

		// Has UUID — will be handled in chunk 5.
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(alias, aliasFinalizer) {
		controllerutil.AddFinalizer(alias, aliasFinalizer)
		if err := r.Update(ctx, alias); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	opnsenseClient, reason, err := r.buildOPNsenseClient(ctx, alias)
	if err != nil {
		return r.setReadyFailed(ctx, alias, reason, err.Error(), err)
	}
	_ = opnsenseClient // used in subsequent chunks

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AliasReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1alpha1.Alias{}).
		Named("alias").
		Complete(r)
}

// buildOPNsenseClient fetches the referenced OPNsenseConnection and credentials Secret,
// validates them, and returns a ready-to-use OPNsense client.
// The returned string is the status condition Reason to use if an error is returned.
func (r *AliasReconciler) buildOPNsenseClient(ctx context.Context, alias *firewallv1alpha1.Alias) (*opnsense.Client, string, error) {
	conn := &firewallv1alpha1.OPNsenseConnection{}
	if err := r.Get(ctx, types.NamespacedName{Name: alias.Spec.ConnectionRef.Name}, conn); err != nil {
		return nil, "ConnectionNotFound", fmt.Errorf("fetch OPNsenseConnection %q: %w", alias.Spec.ConnectionRef.Name, err)
	}

	readyCond := meta.FindStatusCondition(conn.Status.Conditions, "Ready")
	if readyCond == nil || readyCond.Status != metav1.ConditionTrue {
		return nil, "ConnectionNotReady", fmt.Errorf("OPNsenseConnection %q is not ready", conn.Name)
	}

	secretKey := types.NamespacedName{
		Name:      conn.Spec.Credentials.SecretRef.Name,
		Namespace: conn.Spec.Credentials.SecretRef.Namespace,
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return nil, "CredentialsNotFound", fmt.Errorf("fetch credentials Secret %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}

	apiKey := string(secret.Data["apiKey"])
	apiSecret := string(secret.Data["apiSecret"])
	if apiKey == "" || apiSecret == "" {
		return nil, "CredentialsInvalid", fmt.Errorf("credentials Secret %s/%s must have non-empty 'apiKey' and 'apiSecret'", secretKey.Namespace, secretKey.Name)
	}

	httpClient, err := buildHTTPClient(ctx, r.Client, conn.Spec.TLS)
	if err != nil {
		return nil, "TLSConfigFailed", fmt.Errorf("build TLS client: %w", err)
	}

	return opnsense.NewClient(conn.Spec.URL, apiKey, apiSecret, httpClient), "", nil
}

// setReadyFailed sets the Ready condition to False and returns the cause error.
func (r *AliasReconciler) setReadyFailed(ctx context.Context, alias *firewallv1alpha1.Alias, reason, message string, cause error) (ctrl.Result, error) {
	if err := r.setReadyCondition(ctx, alias, metav1.ConditionFalse, reason, message); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// setReadyCondition updates the Ready status condition on the Alias.
func (r *AliasReconciler) setReadyCondition(ctx context.Context, alias *firewallv1alpha1.Alias, status metav1.ConditionStatus, reason, message string) error {
	meta.SetStatusCondition(&alias.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: alias.Generation,
	})
	if err := r.Status().Update(ctx, alias); err != nil {
		return fmt.Errorf("update Alias status: %w", err)
	}
	return nil
}
