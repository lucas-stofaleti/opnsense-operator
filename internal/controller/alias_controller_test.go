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
	"net/http"
	"net/http/httptest"
	"strings"
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

const (
	statusOKBody     = `{"status":"ok"}`
	statusFailedBody = `{"status":"failed"}`
	resultErrorBody  = `{"result":"error"}`
)

var _ = Describe("Alias Controller", func() {
	ctx := context.Background()

	var reconcileAliasWithContext func(context.Context, string, string) (reconcile.Result, error)
	reconcileAlias := func(name, namespace string) (reconcile.Result, error) {
		return reconcileAliasWithContext(ctx, name, namespace)
	}

	reconcileAliasWithContext = func(reconcileCtx context.Context, name, namespace string) (reconcile.Result, error) {
		r := &AliasReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		return r.Reconcile(reconcileCtx, reconcile.Request{
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

		It("logs finalizer removal after the update succeeds", func() {
			By("deleting the Alias CR to set deletionTimestamp")
			alias := &firewallv1alpha1.Alias{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
			Expect(k8sClient.Delete(ctx, alias)).To(Succeed())

			logs := captureControllerLogs(func(logCtx context.Context) {
				_, err := reconcileAliasWithContext(logCtx, aliasName, aliasNS)
				Expect(err).NotTo(HaveOccurred())
			})

			Expect(logs).To(ContainSubstring("Removed Alias finalizer because no external resource exists"))
			Expect(logs).NotTo(ContainSubstring("Removing finalizer for Alias with no external resource"))
		})
	})

	Context("When the Alias only needs a finalizer", func() {
		const aliasName = "test-alias-finalizer-only"
		const aliasNS = "default"

		BeforeEach(func() {
			alias := &firewallv1alpha1.Alias{
				ObjectMeta: metav1.ObjectMeta{
					Name:      aliasName,
					Namespace: aliasNS,
				},
				Spec: firewallv1alpha1.AliasSpec{
					ConnectionRef: firewallv1alpha1.OPNsenseConnectionReference{Name: "primary"},
					Name:          "allow_http",
					Type:          "host",
					Entries:       []string{"198.51.100.20"},
				},
			}
			Expect(k8sClient.Create(ctx, alias)).To(Succeed())
		})

		AfterEach(func() {
			alias := &firewallv1alpha1.Alias{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias); err == nil {
				alias.Finalizers = nil
				Expect(k8sClient.Update(ctx, alias)).To(Succeed())
				Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
			}
		})

		It("does not log routine reconcile start messages", func() {
			logs := captureControllerLogs(func(logCtx context.Context) {
				_, err := reconcileAliasWithContext(logCtx, aliasName, aliasNS)
				Expect(err).NotTo(HaveOccurred())
			})

			Expect(logs).NotTo(ContainSubstring("Reconciling Alias"))
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
						const newAliasUUID = "cccccccc-cccc-cccc-cccc-cccccccccccc"

						var server *httptest.Server
						var getAliasUUIDResponseBody string
						var getAliasResponseBody string
						var createResponseBody string
						var updateResponseBody string
						var reconfigureResponseBody string

						BeforeEach(func() {
							// Default: alias not found by name (pre-create state).
							getAliasUUIDResponseBody = `[]`

							By("starting a mock OPNsense server")
							server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								w.Header().Set("Content-Type", "application/json")
								switch {
								case strings.HasPrefix(r.URL.Path, "/api/firewall/alias/getAliasUUID"):
									_, _ = fmt.Fprint(w, getAliasUUIDResponseBody)
								case r.URL.Path == "/api/firewall/alias/export":
									_, _ = fmt.Fprint(w, getAliasResponseBody)
								case r.Method == http.MethodPost && r.URL.Path == "/api/firewall/alias/addItem":
									_, _ = fmt.Fprint(w, createResponseBody)
								case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/alias/setItem/"):
									_, _ = fmt.Fprint(w, updateResponseBody)
								case r.Method == http.MethodPost && r.URL.Path == "/api/firewall/alias/reconfigure":
									_, _ = fmt.Fprint(w, reconfigureResponseBody)
								default:
									w.WriteHeader(http.StatusNotFound)
								}
							}))

							By("updating the OPNsenseConnection URL to the mock server")
							conn := &firewallv1alpha1.OPNsenseConnection{}
							Expect(k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn)).To(Succeed())
							conn.Spec.URL = server.URL
							Expect(k8sClient.Update(ctx, conn)).To(Succeed())

							By("updating the credentials Secret with valid keys")
							secret := &corev1.Secret{}
							Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret)).To(Succeed())
							secret.Data = map[string][]byte{
								"apiKey":    []byte("test-api-key"),
								"apiSecret": []byte("test-api-secret"),
							}
							Expect(k8sClient.Update(ctx, secret)).To(Succeed())
						})

						AfterEach(func() {
							server.Close()
						})

						Context("When the alias does not exist in OPNsense", func() {
							Context("and CreateAlias and ReconfigureAliases succeed", func() {
								BeforeEach(func() {
									createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newAliasUUID)
									reconfigureResponseBody = statusOKBody
								})

								It("creates the alias and sets status.uuid, observedGeneration, and Ready=True", func() {
									result, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).NotTo(HaveOccurred())
									Expect(result).To(Equal(reconcile.Result{}))

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.UUID).To(Equal(newAliasUUID))
									Expect(alias.Status.ObservedGeneration).To(Equal(alias.Generation))
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionTrue)),
											HaveField("Reason", Equal("AliasReady")),
										),
									))
								})
							})

							Context("and CreateAlias returns a validation error", func() {
								BeforeEach(func() {
									createResponseBody = `{"result":"failed","validations":{"alias.name":"Name already exists"}}`
								})

								It("sets Ready=False with ValidationFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("ValidationFailed")),
										),
									))
								})
							})

							Context("and CreateAlias returns an unexpected error", func() {
								BeforeEach(func() {
									// "result":"error" is not "saved" and not "failed", so the client
									// returns ErrUnexpectedResponse rather than ErrValidationFailed.
									createResponseBody = resultErrorBody
								})

								It("sets Ready=False with CreateFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("CreateFailed")),
										),
									))
								})
							})

							Context("and CreateAlias succeeds but ReconfigureAliases fails", func() {
								BeforeEach(func() {
									createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newAliasUUID)
									reconfigureResponseBody = statusFailedBody
								})

								It("sets Ready=False with ReconfigureFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("ReconfigureFailed")),
										),
									))
								})
							})
						})

						Context("When the alias already exists in OPNsense", func() {
							const existingAliasUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

							BeforeEach(func() {
								getAliasUUIDResponseBody = fmt.Sprintf(`{"uuid":%q}`, existingAliasUUID)
								reconfigureResponseBody = statusOKBody
							})

							Context("and the spec matches the existing alias", func() {
								BeforeEach(func() {
									// Content matches spec: Entries=["198.51.100.10"], Type=host, Enabled=true
									// (Kubernetes applies +kubebuilder:default=true, so the spec always has Enabled=true
									// when the field is omitted). If UpdateAlias were incorrectly called,
									// updateResponseBody would fail, setting Ready=False — proving the no-op path is taken.
									getAliasResponseBody = fmt.Sprintf(`{"aliases":{"alias":{%q:{"enabled":"1","name":"allow_dns","type":"host","content":"198.51.100.10","description":""}}}}`, existingAliasUUID)
									updateResponseBody = resultErrorBody
								})

								It("sets status.uuid and Ready=True without calling UpdateAlias", func() {
									result, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).NotTo(HaveOccurred())
									Expect(result).To(Equal(reconcile.Result{}))

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.UUID).To(Equal(existingAliasUUID))
									Expect(alias.Status.ObservedGeneration).To(Equal(alias.Generation))
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionTrue)),
											HaveField("Reason", Equal("AliasReady")),
										),
									))
								})
							})

							Context("and the spec differs from the existing alias", func() {
								BeforeEach(func() {
									// Content differs: existing has "10.0.0.1", spec has "198.51.100.10".
									getAliasResponseBody = fmt.Sprintf(`{"aliases":{"alias":{%q:{"enabled":"0","name":"allow_dns","type":"host","content":"10.0.0.1","description":""}}}}`, existingAliasUUID)
									updateResponseBody = `{"result":"saved"}`
								})

								It("updates the alias and sets status.uuid and Ready=True", func() {
									result, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).NotTo(HaveOccurred())
									Expect(result).To(Equal(reconcile.Result{}))

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.UUID).To(Equal(existingAliasUUID))
									Expect(alias.Status.ObservedGeneration).To(Equal(alias.Generation))
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionTrue)),
											HaveField("Reason", Equal("AliasReady")),
										),
									))
								})
							})

							Context("and UpdateAlias returns a validation error", func() {
								BeforeEach(func() {
									getAliasResponseBody = fmt.Sprintf(`{"aliases":{"alias":{%q:{"enabled":"0","name":"allow_dns","type":"host","content":"10.0.0.1","description":""}}}}`, existingAliasUUID)
									updateResponseBody = `{"result":"failed","validations":{"alias.type":"Invalid type"}}`
								})

								It("sets Ready=False with ValidationFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("ValidationFailed")),
										),
									))
								})
							})

							Context("and UpdateAlias returns an unexpected error", func() {
								BeforeEach(func() {
									getAliasResponseBody = fmt.Sprintf(`{"aliases":{"alias":{%q:{"enabled":"0","name":"allow_dns","type":"host","content":"10.0.0.1","description":""}}}}`, existingAliasUUID)
									updateResponseBody = resultErrorBody
								})

								It("sets Ready=False with UpdateFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("UpdateFailed")),
										),
									))
								})
							})

							Context("and UpdateAlias succeeds but ReconfigureAliases fails", func() {
								BeforeEach(func() {
									getAliasResponseBody = fmt.Sprintf(`{"aliases":{"alias":{%q:{"enabled":"0","name":"allow_dns","type":"host","content":"10.0.0.1","description":""}}}}`, existingAliasUUID)
									updateResponseBody = `{"result":"saved"}`
									reconfigureResponseBody = statusFailedBody
								})

								It("sets Ready=False with ReconfigureFailed reason", func() {
									_, err := reconcileAlias(aliasName, aliasNS)
									Expect(err).To(HaveOccurred())

									alias := &firewallv1alpha1.Alias{}
									Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
									Expect(alias.Status.Conditions).To(ContainElement(
										And(
											HaveField("Type", Equal("Ready")),
											HaveField("Status", Equal(metav1.ConditionFalse)),
											HaveField("Reason", Equal("ReconfigureFailed")),
										),
									))
								})
							})
						})
					})
				})
			})
		})
	})

	Context("When the Alias is being deleted with a status UUID", func() {
		const aliasName = "test-alias-delete-uuid"
		const aliasNS = "default"
		const connName = "test-conn-delete-uuid"
		const secretName = "test-conn-delete-uuid-creds"
		const secretNS = "default"
		const testUUID = "514ae60a-a270-47df-afdd-b9cdc6fb5c7f"

		var server *httptest.Server
		var deleteResponseBody string
		var reconfigureResponseBody string

		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/alias/delItem/"):
					_, _ = w.Write([]byte(deleteResponseBody))
				case r.Method == http.MethodPost && r.URL.Path == "/api/firewall/alias/reconfigure":
					_, _ = w.Write([]byte(reconfigureResponseBody))
				default:
					http.Error(w, "unexpected request", http.StatusInternalServerError)
				}
			}))

			By("creating the OPNsenseConnection pointing to the mock server")
			conn := &firewallv1alpha1.OPNsenseConnection{
				ObjectMeta: metav1.ObjectMeta{Name: connName},
				Spec: firewallv1alpha1.OPNsenseConnectionSpec{
					URL: server.URL,
					Credentials: firewallv1alpha1.CredentialsSpec{
						SecretRef: firewallv1alpha1.SecretReference{
							Name:      secretName,
							Namespace: secretNS,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			conn.Status.Conditions = []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "ConnectionVerified",
				Message:            "Connection verified",
				LastTransitionTime: metav1.Now(),
			}}
			Expect(k8sClient.Status().Update(ctx, conn)).To(Succeed())

			By("creating the credentials Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNS},
				Data: map[string][]byte{
					"apiKey":    []byte("test-api-key"),
					"apiSecret": []byte("test-api-secret"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating the Alias CR with a finalizer and status UUID")
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
			alias.Status.UUID = testUUID
			Expect(k8sClient.Status().Update(ctx, alias)).To(Succeed())

			By("deleting the Alias CR to set deletionTimestamp")
			Expect(k8sClient.Delete(ctx, alias)).To(Succeed())
		})

		AfterEach(func() {
			server.Close()
			By("cleaning up the Alias CR")
			alias := &firewallv1alpha1.Alias{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias); err == nil {
				alias.Finalizers = nil
				Expect(k8sClient.Update(ctx, alias)).To(Succeed())
				// The object may already have DeletionTimestamp set; ignore NotFound on Delete.
				if err := k8sClient.Delete(ctx, alias); err != nil && !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
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

		Context("When DeleteAlias succeeds and ReconfigureAliases succeeds", func() {
			BeforeEach(func() {
				deleteResponseBody = `{"result":"deleted"}`
				reconfigureResponseBody = statusOKBody
			})

			It("removes the finalizer and allows the object to be deleted", func() {
				result, err := reconcileAlias(aliasName, aliasNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, &firewallv1alpha1.Alias{})
					return errors.IsNotFound(err)
				}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})

		Context("When DeleteAlias returns ErrAliasNotFound", func() {
			BeforeEach(func() {
				deleteResponseBody = `{"result":"not found"}`
				reconfigureResponseBody = statusOKBody
			})

			It("treats it as already deleted and removes the finalizer", func() {
				result, err := reconcileAlias(aliasName, aliasNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, &firewallv1alpha1.Alias{})
					return errors.IsNotFound(err)
				}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})

		Context("When DeleteAlias fails", func() {
			BeforeEach(func() {
				deleteResponseBody = `{"result":"failed"}`
			})

			It("sets Ready=False with DeleteFailed reason", func() {
				_, err := reconcileAlias(aliasName, aliasNS)
				Expect(err).To(HaveOccurred())

				alias := &firewallv1alpha1.Alias{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
				Expect(alias.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("DeleteFailed")),
					),
				))
			})
		})

		Context("When ReconfigureAliases fails", func() {
			BeforeEach(func() {
				deleteResponseBody = `{"result":"deleted"}`
				reconfigureResponseBody = statusFailedBody
			})

			It("sets Ready=False with ReconfigureFailed reason", func() {
				_, err := reconcileAlias(aliasName, aliasNS)
				Expect(err).To(HaveOccurred())

				alias := &firewallv1alpha1.Alias{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: aliasName, Namespace: aliasNS}, alias)).To(Succeed())
				Expect(alias.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ReconfigureFailed")),
					),
				))
			})
		})
	})
})
