package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
)

func newValidAliasObject(name string) *unstructured.Unstructured {
	alias := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": firewallv1alpha1.GroupVersion.String(),
			"kind":       "Alias",
			"metadata": map[string]any{
				"name":      name,
				"namespace": "default",
			},
			"spec": map[string]any{
				"connectionRef": map[string]any{
					"name": "primary",
				},
				"name":        "allow_dns",
				"type":        "host",
				"entries":     []any{"198.51.100.10", "198.51.100.11"},
				"description": "managed by envtest",
			},
		},
	}
	alias.SetGroupVersionKind(firewallv1alpha1.GroupVersion.WithKind("Alias"))
	return alias
}

func newAliasStatusCarrier(name string) *unstructured.Unstructured {
	alias := &unstructured.Unstructured{}
	alias.SetGroupVersionKind(firewallv1alpha1.GroupVersion.WithKind("Alias"))
	alias.SetName(name)
	alias.SetNamespace("default")
	return alias
}

var _ = Describe("Alias API contract", func() {
	It("stores the declared spec fields and defaults enabled to true", func() {
		alias := newValidAliasObject("alias-contract-valid")
		Expect(k8sClient.Create(ctx, alias)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, alias)
		})

		stored := newAliasStatusCarrier(alias.GetName())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(alias), stored)).To(Succeed())

		connectionName, found, err := unstructured.NestedString(stored.Object, "spec", "connectionRef", "name")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(connectionName).To(Equal("primary"))

		aliasName, found, err := unstructured.NestedString(stored.Object, "spec", "name")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(aliasName).To(Equal("allow_dns"))

		aliasType, found, err := unstructured.NestedString(stored.Object, "spec", "type")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(aliasType).To(Equal("host"))

		entries, found, err := unstructured.NestedStringSlice(stored.Object, "spec", "entries")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(entries).To(Equal([]string{"198.51.100.10", "198.51.100.11"}))

		description, found, err := unstructured.NestedString(stored.Object, "spec", "description")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(description).To(Equal("managed by envtest"))

		enabled, found, err := unstructured.NestedBool(stored.Object, "spec", "enabled")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(enabled).To(BeTrue())
	})

	It("rejects objects missing required Alias spec fields", func() {
		alias := newValidAliasObject("alias-contract-missing-fields")
		unstructured.RemoveNestedField(alias.Object, "spec", "connectionRef")
		unstructured.RemoveNestedField(alias.Object, "spec", "entries")

		err := k8sClient.Create(ctx, alias)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("spec.connectionRef"))
		Expect(err.Error()).To(ContainSubstring("spec.entries"))
	})

	It("stores status uuid and observedGeneration through the status subresource", func() {
		alias := newValidAliasObject("alias-contract-status")
		Expect(k8sClient.Create(ctx, alias)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, alias)
		})

		statusCarrier := newAliasStatusCarrier(alias.GetName())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(alias), statusCarrier)).To(Succeed())

		Expect(unstructured.SetNestedField(statusCarrier.Object, "514ae60a-a270-47df-afdd-b9cdc6fb5c7f", "status", "uuid")).To(Succeed())
		Expect(unstructured.SetNestedField(statusCarrier.Object, int64(3), "status", "observedGeneration")).To(Succeed())
		Expect(unstructured.SetNestedSlice(statusCarrier.Object, []any{
			map[string]any{
				"type":               "Ready",
				"status":             string(metav1.ConditionTrue),
				"reason":             "ConnectionVerified",
				"message":            "Alias is ready",
				"observedGeneration": int64(3),
				"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
			},
		}, "status", "conditions")).To(Succeed())

		Expect(k8sClient.Status().Update(ctx, statusCarrier)).To(Succeed())

		stored := newAliasStatusCarrier(alias.GetName())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(alias), stored)).To(Succeed())

		uuid, found, err := unstructured.NestedString(stored.Object, "status", "uuid")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(uuid).To(Equal("514ae60a-a270-47df-afdd-b9cdc6fb5c7f"))

		observedGeneration, found, err := unstructured.NestedInt64(stored.Object, "status", "observedGeneration")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(observedGeneration).To(Equal(int64(3)))
	})
})
