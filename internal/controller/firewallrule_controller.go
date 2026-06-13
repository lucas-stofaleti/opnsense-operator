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

const firewallRuleFinalizer = "firewall.opnsense.io/firewallrule-finalizer"
const reasonValidationFailed = "ValidationFailed"

// FirewallRuleReconciler reconciles a FirewallRule object
type FirewallRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=firewallrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=firewallrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=firewall.opnsense.io,resources=firewallrules/finalizers,verbs=update

func (r *FirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("firewallrule", req.NamespacedName)

	rule := &firewallv1alpha1.FirewallRule{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !rule.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, rule)
	}

	if !controllerutil.ContainsFinalizer(rule, firewallRuleFinalizer) {
		controllerutil.AddFinalizer(rule, firewallRuleFinalizer)
		if err := r.Update(ctx, rule); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	opnsenseClient, reason, err := r.buildOPNsenseClient(ctx, rule)
	if err != nil {
		return r.setReadyFailed(ctx, rule, reason, err.Error(), err)
	}

	uuid, existing, err := r.resolveExternalRule(ctx, opnsenseClient, rule)
	if err != nil {
		return r.setReadyFailed(ctx, rule, "LookupFailed", err.Error(), err)
	}

	desired := specToRule(rule.Spec, rule.Namespace, rule.Name)

	if existing == nil {
		newUUID, err := opnsenseClient.CreateRule(ctx, desired)
		if err != nil {
			reason := "CreateFailed"
			if errors.Is(err, opnsense.ErrValidationFailed) {
				reason = reasonValidationFailed
			}
			return r.setReadyFailed(ctx, rule, reason, err.Error(), err)
		}
		log.Info("Created FirewallRule in OPNsense", "uuid", newUUID)

		if err := opnsenseClient.ApplyFirewallRules(ctx); err != nil {
			return r.setReadyFailed(ctx, rule, "ApplyFailed", err.Error(), err)
		}

		created, err := opnsenseClient.GetRule(ctx, newUUID)
		if err != nil {
			return r.setReadyFailed(ctx, rule, "GetFailed", err.Error(), err)
		}

		return r.setReadySuccess(ctx, rule, newUUID, created.Sequence)
	}

	if ruleNeedsUpdate(rule.Spec, rule.Namespace, rule.Name, *existing) {
		if err := opnsenseClient.UpdateRule(ctx, uuid, desired); err != nil {
			reason := "UpdateFailed"
			if errors.Is(err, opnsense.ErrFirewallRuleNotFound) {
				reason = "NotFound"
			}
			if errors.Is(err, opnsense.ErrValidationFailed) {
				reason = reasonValidationFailed
			}
			return r.setReadyFailed(ctx, rule, reason, err.Error(), err)
		}
		log.Info("Updated FirewallRule in OPNsense", "uuid", uuid)

		if err := opnsenseClient.ApplyFirewallRules(ctx); err != nil {
			return r.setReadyFailed(ctx, rule, "ApplyFailed", err.Error(), err)
		}

		updated, err := opnsenseClient.GetRule(ctx, uuid)
		if err != nil {
			return r.setReadyFailed(ctx, rule, "GetFailed", err.Error(), err)
		}

		return r.setReadySuccess(ctx, rule, uuid, updated.Sequence)
	}

	// Short-circuit: skip status patch if it already reflects current state.
	readyCond := meta.FindStatusCondition(rule.Status.Conditions, "Ready")
	if rule.Status.UUID == uuid &&
		rule.Status.Sequence == existing.Sequence &&
		rule.Status.ObservedGeneration == rule.Generation &&
		readyCond != nil && readyCond.Status == metav1.ConditionTrue {
		return ctrl.Result{}, nil
	}

	return r.setReadySuccess(ctx, rule, uuid, existing.Sequence)
}

// reconcileDelete handles the deletion path: cleans up the external OPNsense rule
// (if it was ever created), applies the change, and removes the finalizer so
// Kubernetes can garbage-collect the CR.
func (r *FirewallRuleReconciler) reconcileDelete(
	ctx context.Context,
	rule *firewallv1alpha1.FirewallRule,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if !controllerutil.ContainsFinalizer(rule, firewallRuleFinalizer) {
		return ctrl.Result{}, nil
	}

	if rule.Status.UUID == "" {
		controllerutil.RemoveFinalizer(rule, firewallRuleFinalizer)
		if err := r.Update(ctx, rule); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	opnsenseClient, reason, err := r.buildOPNsenseClient(ctx, rule)
	if err != nil {
		return r.setReadyFailed(ctx, rule, reason, err.Error(), err)
	}

	if err := opnsenseClient.DeleteRule(ctx, rule.Status.UUID); err != nil {
		if !errors.Is(err, opnsense.ErrFirewallRuleNotFound) {
			return r.setReadyFailed(ctx, rule, "DeleteFailed", err.Error(), err)
		}
		log.Info("FirewallRule not found in OPNsense, treating as already deleted", "uuid", rule.Status.UUID)
	} else {
		log.Info("Deleted FirewallRule in OPNsense", "uuid", rule.Status.UUID)
	}

	if err := opnsenseClient.ApplyFirewallRules(ctx); err != nil {
		return r.setReadyFailed(ctx, rule, "ApplyFailed", err.Error(), err)
	}

	controllerutil.RemoveFinalizer(rule, firewallRuleFinalizer)
	if err := r.Update(ctx, rule); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// resolveExternalRule determines whether the rule exists in OPNsense and returns its
// current UUID and state. If status.UUID is set, it tries GetRule first; if that returns
// not found (stale UUID), it falls back to SearchRuleByManagedSuffix.
// Returns ("", nil, nil) when no rule is found.
func (r *FirewallRuleReconciler) resolveExternalRule(
	ctx context.Context,
	c *opnsense.Client,
	rule *firewallv1alpha1.FirewallRule,
) (string, *opnsense.FirewallRule, error) {
	log := logf.FromContext(ctx)

	if rule.Status.UUID != "" {
		existing, err := c.GetRule(ctx, rule.Status.UUID)
		if err == nil {
			return rule.Status.UUID, &existing, nil
		}
		if !errors.Is(err, opnsense.ErrFirewallRuleNotFound) {
			return "", nil, err
		}
		// UUID is stale — fall through to suffix search.
		log.Info("Stale UUID in status, falling back to suffix search", "uuid", rule.Status.UUID)
	}

	suffix := rule.Namespace + "/" + rule.Name
	uuids, err := c.SearchRuleByManagedSuffix(ctx, suffix)
	if err != nil {
		return "", nil, err
	}

	switch len(uuids) {
	case 0:
		return "", nil, nil
	case 1:
		existing, err := c.GetRule(ctx, uuids[0])
		if err != nil {
			return "", nil, err
		}
		return uuids[0], &existing, nil
	default:
		return "", nil, fmt.Errorf(
			"found %d rules matching managed suffix %q, expected at most 1",
			len(uuids), suffix)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1alpha1.FirewallRule{}).
		Named("firewallrule").
		Complete(r)
}

// buildOPNsenseClient fetches the referenced OPNsenseConnection and credentials Secret,
// validates them, and returns a ready-to-use OPNsense client.
// The returned string is the status condition Reason to use if an error is returned.
func (r *FirewallRuleReconciler) buildOPNsenseClient(ctx context.Context, rule *firewallv1alpha1.FirewallRule) (*opnsense.Client, string, error) {
	conn := &firewallv1alpha1.OPNsenseConnection{}
	if err := r.Get(ctx, types.NamespacedName{Name: rule.Spec.ConnectionRef.Name}, conn); err != nil {
		return nil, "ConnectionNotFound", fmt.Errorf("fetch OPNsenseConnection %q: %w", rule.Spec.ConnectionRef.Name, err)
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
func (r *FirewallRuleReconciler) setReadyFailed(ctx context.Context, rule *firewallv1alpha1.FirewallRule, reason, message string, cause error) (ctrl.Result, error) {
	if err := r.setReadyCondition(ctx, rule, metav1.ConditionFalse, reason, message); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, cause
}

// setReadySuccess sets the Ready condition to True and stores UUID, Sequence, and ObservedGeneration.
func (r *FirewallRuleReconciler) setReadySuccess(ctx context.Context, rule *firewallv1alpha1.FirewallRule, uuid, sequence string) (ctrl.Result, error) {
	rule.Status.UUID = uuid
	rule.Status.Sequence = sequence
	rule.Status.ObservedGeneration = rule.Generation
	if err := r.setReadyCondition(ctx, rule, metav1.ConditionTrue, "FirewallRuleReady", "FirewallRule is in sync with OPNsense"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// setReadyCondition updates the Ready status condition on the FirewallRule.
func (r *FirewallRuleReconciler) setReadyCondition(ctx context.Context, rule *firewallv1alpha1.FirewallRule, status metav1.ConditionStatus, reason, message string) error {
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: rule.Generation,
	})
	if err := r.Status().Update(ctx, rule); err != nil {
		return fmt.Errorf("update FirewallRule status: %w", err)
	}
	return nil
}

// specToRule converts a FirewallRuleSpec to an opnsense.FirewallRule, appending the
// managed suffix to the description so the controller can identify the rule later.
func specToRule(spec firewallv1alpha1.FirewallRuleSpec, namespace, name string) opnsense.FirewallRule {
	suffix := "[opnsense-operator:" + namespace + "/" + name + "]"
	description := strings.TrimSpace(spec.Description + " " + suffix)

	sequence := ""
	if spec.Sequence != nil {
		sequence = fmt.Sprintf("%d", *spec.Sequence)
	}

	return opnsense.FirewallRule{
		Enabled:         spec.Enabled,
		Action:          spec.Action,
		Interface:       spec.Interface,
		Direction:       spec.Direction,
		IPProtocol:      spec.IPProtocol,
		Protocol:        spec.Protocol,
		SourceNet:       spec.Source.Net,
		SourceNot:       spec.Source.Not,
		SourcePort:      spec.Source.Port,
		DestinationNet:  spec.Destination.Net,
		DestinationNot:  spec.Destination.Not,
		DestinationPort: spec.Destination.Port,
		Sequence:        sequence,
		Log:             spec.Log,
		Quick:           spec.Quick,
		Description:     description,
	}
}

// ruleNeedsUpdate returns true if the desired spec differs from the current
// external rule state in any field that the operator manages.
// Sequence is only compared when spec.Sequence is explicitly set; when omitted,
// OPNsense owns the value and drift-detecting on it would cause unnecessary updates.
func ruleNeedsUpdate(spec firewallv1alpha1.FirewallRuleSpec, namespace, name string, existing opnsense.FirewallRule) bool {
	desired := specToRule(spec, namespace, name)

	if desired.Enabled != existing.Enabled ||
		desired.Action != existing.Action ||
		desired.Interface != existing.Interface ||
		desired.Direction != existing.Direction ||
		desired.IPProtocol != existing.IPProtocol ||
		desired.Protocol != existing.Protocol ||
		desired.SourceNet != existing.SourceNet ||
		desired.SourceNot != existing.SourceNot ||
		desired.SourcePort != existing.SourcePort ||
		desired.DestinationNet != existing.DestinationNet ||
		desired.DestinationNot != existing.DestinationNot ||
		desired.DestinationPort != existing.DestinationPort ||
		desired.Log != existing.Log ||
		desired.Quick != existing.Quick ||
		desired.Description != existing.Description {
		return true
	}

	if spec.Sequence != nil && desired.Sequence != existing.Sequence {
		return true
	}

	return false
}
