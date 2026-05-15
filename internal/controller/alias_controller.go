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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
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
		// Being deleted — handled in a later chunk.
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(alias, aliasFinalizer) {
		controllerutil.AddFinalizer(alias, aliasFinalizer)
		if err := r.Update(ctx, alias); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AliasReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1alpha1.Alias{}).
		Named("alias").
		Complete(r)
}
