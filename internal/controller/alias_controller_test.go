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
				Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
			}
		})

		It("returns empty result without error", func() {
			result, err := reconcileAlias(aliasName, aliasNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})
})
