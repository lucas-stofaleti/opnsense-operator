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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
)

var _ = Describe("Alias Controller", func() {
	ctx := context.Background()

	reconcileAlias := func(name, namespace string) (reconcile.Result, error) {
		r := &AliasReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		return r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
		})
	}

	Context("When the Alias does not exist in Kubernetes", func() {
		It("returns empty result without error", func() {
			result, err := reconcileAlias("does-not-exist", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	Context("When the Alias exists in Kubernetes", func() {
		const aliasName = "test-alias"
		const aliasNS = "default"

		BeforeEach(func() {
			By("creating the Alias CR")
			alias := &firewallv1alpha1.Alias{
				ObjectMeta: metav1.ObjectMeta{
					Name:      aliasName,
					Namespace: aliasNS,
				},
				Spec: firewallv1alpha1.AliasSpec{
					ConnectionRef: firewallv1alpha1.OPNsenseConnectionReference{Name: "primary"},
					Name:          "allow_dns",
					Type:          "host",
					Entries:       []string{"198.51.100.10"},
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, &firewallv1alpha1.Alias{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, alias)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("deleting the Alias CR")
			alias := &firewallv1alpha1.Alias{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias); err == nil {
				alias.Finalizers = nil
				Expect(k8sClient.Update(ctx, alias)).To(Succeed())
				Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
			}
		})

		It("returns empty result without error", func() {
			result, err := reconcileAlias(aliasName, aliasNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})

		It("adds the finalizer", func() {
			_, err := reconcileAlias(aliasName, aliasNS)
			Expect(err).NotTo(HaveOccurred())

			alias := &firewallv1alpha1.Alias{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
			Expect(alias.Finalizers).To(ContainElement("firewall.opnsense.io/finalizer"))
		})
	})

	Context("When the Alias is being deleted with no status UUID", func() {
		const aliasName = "test-alias-delete-no-uuid"
		const aliasNS = "default"

		BeforeEach(func() {
			By("creating the Alias CR with a finalizer already set")
			alias := &firewallv1alpha1.Alias{
				ObjectMeta: metav1.ObjectMeta{
					Name:       aliasName,
					Namespace:  aliasNS,
					Finalizers: []string{aliasFinalizer},
				},
				Spec: firewallv1alpha1.AliasSpec{
					ConnectionRef: firewallv1alpha1.OPNsenseConnectionReference{Name: "primary"},
					Name:          "allow_dns",
					Type:          "host",
					Entries:       []string{"198.51.100.10"},
				},
			}
			Expect(k8sClient.Create(ctx, alias)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the Alias CR if it still exists")
			alias := &firewallv1alpha1.Alias{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias); err == nil {
				alias.Finalizers = nil
				Expect(k8sClient.Update(ctx, alias)).To(Succeed())
				Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
			}
		})

		It("removes the finalizer and allows the object to be deleted", func() {
			By("deleting the Alias CR to set deletionTimestamp")
			alias := &firewallv1alpha1.Alias{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
			Expect(k8sClient.Delete(ctx, alias)).To(Succeed())

			By("reconciling — should remove the finalizer")
			result, err := reconcileAlias(aliasName, aliasNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			By("verifying the object is eventually gone")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, &firewallv1alpha1.Alias{})
				return errors.IsNotFound(err)
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})
})
