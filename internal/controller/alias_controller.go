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
	"errors"
	"fmt"
	"strings"

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

		opnsenseClient, reason, err := r.buildOPNsenseClient(ctx, alias)
		if err != nil {
			return r.setReadyFailed(ctx, alias, reason, err.Error(), err)
		}
		if err := opnsenseClient.DeleteAlias(ctx, alias.Status.UUID); err != nil {
			if !errors.Is(err, opnsense.ErrAliasNotFound) {
				return r.setReadyFailed(ctx, alias, "DeleteFailed", err.Error(), err)
			}
			log.Info("Alias not found in OPNsense, treating as already deleted", "uuid", alias.Status.UUID)
		} else {
			log.Info("Deleted Alias in OPNsense", "uuid", alias.Status.UUID)
		}
		if err := opnsenseClient.ReconfigureAliases(ctx); err != nil {
			return r.setReadyFailed(ctx, alias, "ReconfigureFailed", err.Error(), err)
		}
		controllerutil.RemoveFinalizer(alias, aliasFinalizer)
		if err := r.Update(ctx, alias); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
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

	resolvedUUID, existingAlias, err := r.resolveExternalAlias(ctx, opnsenseClient, alias)
	if err != nil {
		return r.setReadyFailed(ctx, alias, "LookupFailed", err.Error(), err)
	}

	specAlias := specToAlias(alias.Spec)

	if existingAlias == nil {
		newUUID, err := opnsenseClient.CreateAlias(ctx, specAlias)
		if err != nil {
			reason := "CreateFailed"
			if errors.Is(err, opnsense.ErrValidationFailed) {
				reason = "ValidationFailed"
			}
			return r.setReadyFailed(ctx, alias, reason, err.Error(), err)
		}
		resolvedUUID = newUUID
		log.Info("Created Alias in OPNsense", "uuid", resolvedUUID)

		if err := opnsenseClient.ReconfigureAliases(ctx); err != nil {
			return r.setReadyFailed(ctx, alias, "ReconfigureFailed", err.Error(), err)
		}

		return r.setReadySuccess(ctx, alias, resolvedUUID)
	}

	_ = resolvedUUID  // used in chunks 9-10
	_ = existingAlias // used in chunks 9-10

	return ctrl.Result{}, nil
}

// resolveExternalAlias determines whether the alias exists in OPNsense and returns its
// current UUID and state. If status.uuid is set, it tries GetAlias first; if that returns
// not found (stale UUID), it falls back to GetAliasUUIDByName. If no UUID is set, it goes
// directly to GetAliasUUIDByName. Returns ("", nil, nil) when the alias does not exist.
func (r *AliasReconciler) resolveExternalAlias(ctx context.Context, c *opnsense.Client, alias *firewallv1alpha1.Alias) (string, *opnsense.Alias, error) {
	if alias.Status.UUID != "" {
		existing, err := c.GetAlias(ctx, alias.Status.UUID)
		if err == nil {
			return alias.Status.UUID, &existing, nil
		}
		if !errors.Is(err, opnsense.ErrAliasNotFound) {
			return "", nil, err
		}
		// UUID is stale — fall through to name lookup.
	}

	uuid, err := c.GetAliasUUIDByName(ctx, alias.Spec.Name)
	if err != nil {
		if errors.Is(err, opnsense.ErrAliasNotFound) {
			return "", nil, nil
		}
		return "", nil, err
	}

	existing, err := c.GetAlias(ctx, uuid)
	if err != nil {
		return "", nil, err
	}

	return uuid, &existing, nil
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

// setReadySuccess sets the Ready condition to True, stores the UUID and observedGeneration in status.
func (r *AliasReconciler) setReadySuccess(ctx context.Context, alias *firewallv1alpha1.Alias, uuid string) (ctrl.Result, error) {
	alias.Status.UUID = uuid
	alias.Status.ObservedGeneration = alias.Generation
	if err := r.setReadyCondition(ctx, alias, metav1.ConditionTrue, "AliasReady", "Alias is in sync with OPNsense"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
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

// specToAlias converts an AliasSpec to the opnsense.Alias representation.
// Entries are joined with newlines as required by the OPNsense API.
func specToAlias(spec firewallv1alpha1.AliasSpec) opnsense.Alias {
	return opnsense.Alias{
		Enabled:     spec.Enabled,
		Name:        spec.Name,
		Type:        spec.Type,
		Content:     strings.Join(spec.Entries, "\n"),
		Description: spec.Description,
	}
}
