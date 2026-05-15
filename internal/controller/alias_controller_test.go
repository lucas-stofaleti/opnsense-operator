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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

	Context("When the Alias has a finalizer and a connectionRef", func() {
		const aliasName = "test-alias-with-conn"
		const aliasNS = "default"
		const connName = "test-conn"
		const secretName = "test-conn-creds"
		const secretNS = "default"

		BeforeEach(func() {
			By("creating the Alias CR with a finalizer")
			alias := &firewallv1alpha1.Alias{
				ObjectMeta: metav1.ObjectMeta{
					Name:       aliasName,
					Namespace:  aliasNS,
					Finalizers: []string{aliasFinalizer},
				},
				Spec: firewallv1alpha1.AliasSpec{
					ConnectionRef: firewallv1alpha1.OPNsenseConnectionReference{Name: connName},
					Name:          "allow_dns",
					Type:          "host",
					Entries:       []string{"198.51.100.10"},
				},
			}
			Expect(k8sClient.Create(ctx, alias)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the Alias CR")
			alias := &firewallv1alpha1.Alias{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias); err == nil {
				alias.Finalizers = nil
				Expect(k8sClient.Update(ctx, alias)).To(Succeed())
				Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
			}
			By("cleaning up the OPNsenseConnection")
			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}
			By("cleaning up the credentials Secret")
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret); err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("sets Ready=False when the OPNsenseConnection is not found", func() {
			_, err := reconcileAlias(aliasName, aliasNS)
			Expect(err).To(HaveOccurred())

			alias := &firewallv1alpha1.Alias{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
			Expect(alias.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("ConnectionNotFound")),
				),
			))
		})

		Context("When the OPNsenseConnection exists but is not Ready", func() {
			BeforeEach(func() {
				By("creating the OPNsenseConnection without a Ready condition")
				conn := &firewallv1alpha1.OPNsenseConnection{
					ObjectMeta: metav1.ObjectMeta{Name: connName},
					Spec: firewallv1alpha1.OPNsenseConnectionSpec{
						URL: "http://opnsense.example.com",
						Credentials: firewallv1alpha1.CredentialsSpec{
							SecretRef: firewallv1alpha1.SecretReference{
								Name:      secretName,
								Namespace: secretNS,
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			})

			It("sets Ready=False with ConnectionNotReady reason", func() {
				_, err := reconcileAlias(aliasName, aliasNS)
				Expect(err).To(HaveOccurred())

				alias := &firewallv1alpha1.Alias{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
				Expect(alias.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ConnectionNotReady")),
					),
				))
			})

			Context("When the OPNsenseConnection is Ready", func() {
				BeforeEach(func() {
					By("setting the OPNsenseConnection Ready=True")
					conn := &firewallv1alpha1.OPNsenseConnection{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn)).To(Succeed())
					conn.Status.Conditions = []metav1.Condition{{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "ConnectionVerified",
						Message:            "Connection verified",
						LastTransitionTime: metav1.Now(),
					}}
					Expect(k8sClient.Status().Update(ctx, conn)).To(Succeed())
				})

				It("sets Ready=False when the credentials Secret is not found", func() {
					_, err := reconcileAlias(aliasName, aliasNS)
					Expect(err).To(HaveOccurred())

					alias := &firewallv1alpha1.Alias{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
					Expect(alias.Status.Conditions).To(ContainElement(
						And(
							HaveField("Type", Equal("Ready")),
							HaveField("Status", Equal(metav1.ConditionFalse)),
							HaveField("Reason", Equal("CredentialsNotFound")),
						),
					))
				})

				Context("When the credentials Secret exists with empty data", func() {
					BeforeEach(func() {
						By("creating the credentials Secret without required keys")
						secret := &corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Name:      secretName,
								Namespace: secretNS,
							},
							Data: map[string][]byte{},
						}
						Expect(k8sClient.Create(ctx, secret)).To(Succeed())
					})

					It("sets Ready=False when apiKey or apiSecret are missing", func() {
						_, err := reconcileAlias(aliasName, aliasNS)
						Expect(err).To(HaveOccurred())

						alias := &firewallv1alpha1.Alias{}
						Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
						Expect(alias.Status.Conditions).To(ContainElement(
							And(
								HaveField("Type", Equal("Ready")),
								HaveField("Status", Equal(metav1.ConditionFalse)),
								HaveField("Reason", Equal("CredentialsInvalid")),
							),
						))
					})

					Context("When credentials are valid", func() {
						BeforeEach(func() {
							By("updating the credentials Secret with valid keys")
							secret := &corev1.Secret{}
							Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret)).To(Succeed())
							secret.Data = map[string][]byte{
								"apiKey":    []byte("test-api-key"),
								"apiSecret": []byte("test-api-secret"),
							}
							Expect(k8sClient.Update(ctx, secret)).To(Succeed())
						})

						It("builds the client successfully and returns no error", func() {
							result, err := reconcileAlias(aliasName, aliasNS)
							Expect(err).NotTo(HaveOccurred())
							Expect(result).To(Equal(reconcile.Result{}))

							alias := &firewallv1alpha1.Alias{}
							Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
							Expect(alias.Status.Conditions).To(BeEmpty())
						})
					})
				})
			})
		})
	})
})
