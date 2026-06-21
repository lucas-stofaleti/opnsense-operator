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

// applyOKBody is the OPNsense apply response for successful firewall rule apply.
const (
	applyOKBody       = `{"status":"OK"}`
	applyFilterPath   = "/api/firewall/filter/apply"
	addRulePath       = "/api/firewall/filter/addRule"
	searchEmptyRows   = `{"rows":[]}`
	resultSavedBody   = `{"result":"saved"}`
	resultDeletedBody = `{"result":"deleted"}`
)

var _ = Describe("FirewallRule Controller", func() {
	ctx := context.Background()

	reconcileRule := func(name, namespace string) (reconcile.Result, error) {
		r := &FirewallRuleReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		return r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
		})
	}

	// baseSpec returns a minimal valid FirewallRuleSpec for tests.
	baseSpec := func(connName string) firewallv1alpha1.FirewallRuleSpec {
		return firewallv1alpha1.FirewallRuleSpec{
			ConnectionRef: firewallv1alpha1.OPNsenseConnectionReference{Name: connName},
			Action:        "pass",
			Direction:     "in",
			IPProtocol:    "inet",
			Protocol:      "any",
			Quick:         true,
			Enabled:       true,
			Source:        firewallv1alpha1.FirewallRuleEndpoint{Net: "any"},
			Destination:   firewallv1alpha1.FirewallRuleEndpoint{Net: "any"},
		}
	}

	// createReadyConnection creates an OPNsenseConnection and credentials Secret pointing at serverURL,
	// and marks the connection Ready=True. Returns a cleanup function.
	createReadyConnection := func(connName, secretName, serverURL string) func() {
		conn := &firewallv1alpha1.OPNsenseConnection{
			ObjectMeta: metav1.ObjectMeta{Name: connName},
			Spec: firewallv1alpha1.OPNsenseConnectionSpec{
				URL: serverURL,
				Credentials: firewallv1alpha1.CredentialsSpec{
					SecretRef: firewallv1alpha1.SecretReference{
						Name:      secretName,
						Namespace: "default",
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

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
			Data: map[string][]byte{
				"apiKey":    []byte("test-api-key"),
				"apiSecret": []byte("test-api-secret"),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		return func() {
			c := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, c); err == nil {
				_ = k8sClient.Delete(ctx, c)
			}
			s := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: "default"}, s); err == nil {
				_ = k8sClient.Delete(ctx, s)
			}
		}
	}

	// deleteRuleCleanup removes a FirewallRule CR (stripping finalizers first).
	deleteRuleCleanup := func(name, namespace string) {
		rule := &firewallv1alpha1.FirewallRule{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, rule); err == nil {
			rule.Finalizers = nil
			_ = k8sClient.Update(ctx, rule)
			_ = k8sClient.Delete(ctx, rule)
		}
	}

	// --- Test 1: CR does not exist ---
	Context("When the FirewallRule CR does not exist in Kubernetes", func() {
		It("returns empty result without error", func() {
			result, err := reconcileRule("does-not-exist", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	// --- Test 2: ConnectionRef not found ---
	Context("When the FirewallRule exists but ConnectionRef is not found", func() {
		const ruleName = "fwr-conn-not-found"
		const ruleNS = "default"

		BeforeEach(func() {
			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec("no-such-connection"),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

		It("sets Ready=False with ConnectionNotFound reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("ConnectionNotFound")),
				),
			))
		})
	})

	// --- Test 3: Connection exists but Ready=False ---
	Context("When the Connection exists but is not Ready", func() {
		const ruleName = "fwr-conn-not-ready"
		const ruleNS = "default"
		const connName = "fwr-conn-not-ready-conn"

		BeforeEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{
				ObjectMeta: metav1.ObjectMeta{Name: connName},
				Spec: firewallv1alpha1.OPNsenseConnectionSpec{
					URL: "http://opnsense.example.com",
					Credentials: firewallv1alpha1.CredentialsSpec{
						SecretRef: firewallv1alpha1.SecretReference{
							Name:      "dummy-secret",
							Namespace: "default",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, conn)).To(Succeed())

			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec(connName),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() {
			deleteRuleCleanup(ruleName, ruleNS)
			c := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, c); err == nil {
				_ = k8sClient.Delete(ctx, c)
			}
		})

		It("sets Ready=False with ConnectionNotReady reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("ConnectionNotReady")),
				),
			))
		})
	})

	// --- Test 4: credentials Secret missing ---
	Context("When credentials Secret is missing", func() {
		const ruleName = "fwr-creds-missing"
		const ruleNS = "default"
		const connName = "fwr-creds-missing-conn"

		BeforeEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{
				ObjectMeta: metav1.ObjectMeta{Name: connName},
				Spec: firewallv1alpha1.OPNsenseConnectionSpec{
					URL: "http://opnsense.example.com",
					Credentials: firewallv1alpha1.CredentialsSpec{
						SecretRef: firewallv1alpha1.SecretReference{
							Name:      "no-such-secret",
							Namespace: "default",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			conn.Status.Conditions = []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "ConnectionVerified",
				Message:            "ok",
				LastTransitionTime: metav1.Now(),
			}}
			Expect(k8sClient.Status().Update(ctx, conn)).To(Succeed())

			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec(connName),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() {
			deleteRuleCleanup(ruleName, ruleNS)
			c := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, c); err == nil {
				_ = k8sClient.Delete(ctx, c)
			}
		})

		It("sets Ready=False with CredentialsNotFound reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("CredentialsNotFound")),
				),
			))
		})
	})

	// --- Test 4b: credentials Secret exists but apiKey/apiSecret are empty ---
	Context("When credentials Secret exists but apiKey/apiSecret are empty", func() {
		const ruleName = "fwr-creds-invalid"
		const ruleNS = "default"
		const connName = "fwr-creds-invalid-conn"
		const secretName = "fwr-creds-invalid-secret"

		BeforeEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{
				ObjectMeta: metav1.ObjectMeta{Name: connName},
				Spec: firewallv1alpha1.OPNsenseConnectionSpec{
					URL: "http://opnsense.example.com",
					Credentials: firewallv1alpha1.CredentialsSpec{
						SecretRef: firewallv1alpha1.SecretReference{
							Name:      secretName,
							Namespace: "default",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			conn.Status.Conditions = []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "ConnectionVerified",
				Message:            "ok",
				LastTransitionTime: metav1.Now(),
			}}
			Expect(k8sClient.Status().Update(ctx, conn)).To(Succeed())

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
				Data:       map[string][]byte{},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec(connName),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() {
			deleteRuleCleanup(ruleName, ruleNS)
			c := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, c); err == nil {
				_ = k8sClient.Delete(ctx, c)
			}
			s := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: "default"}, s); err == nil {
				_ = k8sClient.Delete(ctx, s)
			}
		})

		It("sets Ready=False with CredentialsInvalid reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("CredentialsInvalid")),
				),
			))
		})
	})

	// --- Tests 5–11: full OPNsense mock ---
	Context("When all prerequisites are ready", func() {
		const ruleName = "fwr-main"
		const ruleNS = "default"
		const connName = "fwr-main-conn"
		const secretName = "fwr-main-creds"
		const newUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		const existingUUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

		var server *httptest.Server
		var searchResponseBody string
		var getRuleResponseBody string
		var createResponseBody string
		var updateResponseBody string
		var applyResponseBody string
		var cleanupConn func()

		// buildGetRuleBody returns a mock getRule/{uuid} response for a basic "pass in any→any" rule.
		buildGetRuleBody := func(action, sequence string) string {
			return fmt.Sprintf(`{"rule":{`+
				`"enabled":"1",`+
				`"sequence":%q,`+
				`"action":{%q:{"value":"Pass","selected":1}},`+
				`"interface":{},`+
				`"direction":{"in":{"value":"In","selected":1}},`+
				`"ipprotocol":{"inet":{"value":"IPv4","selected":1}},`+
				`"protocol":{"any":{"value":"any","selected":1}},`+
				`"source_net":"any","source_not":"0","source_port":"",`+
				`"destination_net":"any","destination_not":"0","destination_port":"",`+
				`"log":"0","quick":"1",`+
				`"description":"[opnsense-operator:%s/%s]"`+
				`}}`,
				sequence, action, ruleNS, ruleName)
		}

		BeforeEach(func() {
			applyResponseBody = applyOKBody

			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
					_, _ = fmt.Fprint(w, searchResponseBody)
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
					_, _ = fmt.Fprint(w, getRuleResponseBody)
				case r.Method == http.MethodPost && r.URL.Path == addRulePath:
					_, _ = fmt.Fprint(w, createResponseBody)
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/setRule/"):
					_, _ = fmt.Fprint(w, updateResponseBody)
				case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
					_, _ = fmt.Fprint(w, applyResponseBody)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			cleanupConn = createReadyConnection(connName, secretName, server.URL)

			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec(connName),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() {
			server.Close()
			deleteRuleCleanup(ruleName, ruleNS)
			cleanupConn()
		})

		// --- Test 5: OPNsense search returns 0 results — create path ---
		Context("and OPNsense has no matching rule (create path)", func() {
			BeforeEach(func() {
				searchResponseBody = searchEmptyRows
				createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newUUID)
				getRuleResponseBody = buildGetRuleBody("pass", "1")
			})

			It("creates the rule, applies, and sets Ready=True with UUID and Sequence", func() {
				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.UUID).To(Equal(newUUID))
				Expect(rule.Status.Sequence).NotTo(BeEmpty())
				Expect(rule.Status.ObservedGeneration).To(Equal(rule.Generation))
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionTrue)),
						HaveField("Reason", Equal("FirewallRuleReady")),
					),
				))
			})
		})

		// --- Test 6: rule already in sync (no-op path) ---
		Context("and OPNsense rule is already in sync (no drift)", func() {
			BeforeEach(func() {
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				getRuleResponseBody = buildGetRuleBody("pass", "10")
				// If UpdateRule is called, we return an error to prove it was NOT called.
				updateResponseBody = resultErrorBody
			})

			It("does not call UpdateRule and sets Ready=True (idempotent)", func() {
				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.UUID).To(Equal(existingUUID))
				Expect(rule.Status.Sequence).To(Equal("10"))
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionTrue)),
					),
				))

				// Second reconcile should be a true no-op (no status patch).
				result2, err2 := reconcileRule(ruleName, ruleNS)
				Expect(err2).NotTo(HaveOccurred())
				Expect(result2).To(Equal(reconcile.Result{}))
			})
		})

		// --- Test 7: rule drifted — update path ---
		Context("and OPNsense rule has drifted (action changed)", func() {
			BeforeEach(func() {
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				// Existing rule has action=block, but spec says action=pass.
				getRuleResponseBody = buildGetRuleBody("block", "5")
				updateResponseBody = resultSavedBody
				// After update, getRule is called again — return updated state.
				// The server handler always uses the same getRuleResponseBody; we'll
				// set it to the post-update state before the test runs.
			})

			It("calls UpdateRule, applies, and sets Ready=True", func() {
				// Override: after update the server returns a "pass" rule.
				updatedBody := buildGetRuleBody("pass", "5")
				callCount := 0
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
						_, _ = fmt.Fprint(w, searchResponseBody)
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
						callCount++
						if callCount == 1 {
							_, _ = fmt.Fprint(w, getRuleResponseBody) // drifted
						} else {
							_, _ = fmt.Fprint(w, updatedBody) // post-update
						}
					case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/setRule/"):
						_, _ = fmt.Fprint(w, updateResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
						_, _ = fmt.Fprint(w, applyResponseBody)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.UUID).To(Equal(existingUUID))
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionTrue)),
					),
				))
			})
		})

		// --- Test 8b: LookupFailed when GetRule returns a non-not-found error for status.UUID ---
		Context("and GetRule returns a non-not-found error for status.UUID", func() {
			const staleUUID = "error-0000-0000-0000-000000000000"

			BeforeEach(func() {
				// Prime status.UUID so resolveExternalRule calls GetRule first.
				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				rule.Status.UUID = staleUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
			})

			It("sets Ready=False with LookupFailed reason", func() {
				// Override server to return HTTP 500 for getRule — triggers ErrUnexpectedResponse.
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/") {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = fmt.Fprint(w, `{"error":"internal"}`)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				})

				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("LookupFailed")),
					),
				))
			})
		})

		// --- Test 8: search returns N>1 UUIDs ---
		Context("and OPNsense search returns multiple UUIDs", func() {
			BeforeEach(func() {
				searchResponseBody = `{"rows":[{"uuid":"uuid-1"},{"uuid":"uuid-2"}]}`
			})

			It("sets Ready=False with LookupFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("LookupFailed")),
					),
				))
			})
		})

		// --- Test 9: stale UUID in status → fallback to search → create ---
		Context("and status.UUID is stale (getRule returns not found), search returns 0", func() {
			const staleUUID = "stale-0000-0000-0000-000000000000"

			BeforeEach(func() {
				// Prime the rule with a stale UUID in status.
				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				rule.Status.UUID = staleUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())

				// getRule for stale UUID returns [] (not found).
				// search returns 0 results → create path.
				searchResponseBody = searchEmptyRows
				createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newUUID)
				getRuleResponseBody = buildGetRuleBody("pass", "1")
			})

			It("falls back to search, creates the rule, and sets Ready=True", func() {
				callCount := 0
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
						callCount++
						if callCount == 1 {
							// First call is for stale UUID — return not-found ([]).
							_, _ = fmt.Fprint(w, `[]`)
						} else {
							// Second call is post-create read-back.
							_, _ = fmt.Fprint(w, getRuleResponseBody)
						}
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
						_, _ = fmt.Fprint(w, searchResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == addRulePath:
						_, _ = fmt.Fprint(w, createResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
						_, _ = fmt.Fprint(w, applyResponseBody)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.UUID).To(Equal(newUUID))
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionTrue)),
					),
				))
			})
		})

		// --- Test 10: CreateRule returns validation error ---
		Context("and CreateRule returns a validation error", func() {
			BeforeEach(func() {
				searchResponseBody = searchEmptyRows
				createResponseBody = `{"result":"failed","validations":{"rule.action":"Invalid action"}}`
			})

			It("sets Ready=False with ValidationFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ValidationFailed")),
					),
				))
			})
		})

		// --- Test 11: ApplyFirewallRules fails after create ---
		Context("and ApplyFirewallRules fails after create", func() {
			BeforeEach(func() {
				searchResponseBody = searchEmptyRows
				createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newUUID)
				applyResponseBody = statusFailedBody
			})

			It("sets Ready=False with ApplyFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ApplyFailed")),
					),
				))
			})
		})

		// --- Test 11g: GetFailed after CreateRule and Apply succeed ---
		Context("and GetRule fails after CreateRule and Apply succeed", func() {
			BeforeEach(func() {
				searchResponseBody = searchEmptyRows
				createResponseBody = fmt.Sprintf(`{"result":"saved","uuid":%q}`, newUUID)
				applyResponseBody = applyOKBody
			})

			It("sets Ready=False with GetFailed reason", func() {
				// Override server: create and apply succeed, but getRule returns 500.
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
						_, _ = fmt.Fprint(w, searchResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == addRulePath:
						_, _ = fmt.Fprint(w, createResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
						_, _ = fmt.Fprint(w, applyResponseBody)
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = fmt.Fprint(w, `{"error":"internal"}`)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("GetFailed")),
					),
				))
			})
		})

		// --- Test 11b: CreateRule returns a generic (non-validation) error ---
		Context("and CreateRule returns a generic error", func() {
			BeforeEach(func() {
				searchResponseBody = searchEmptyRows
				// "result":"error" is not "saved" and not "failed", so the client
				// returns ErrUnexpectedResponse rather than ErrValidationFailed.
				createResponseBody = resultErrorBody
			})

			It("sets Ready=False with CreateFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("CreateFailed")),
					),
				))
			})
		})

		// --- Test 11c: UpdateRule returns ErrFirewallRuleNotFound ---
		Context("and UpdateRule returns ErrFirewallRuleNotFound", func() {
			BeforeEach(func() {
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				// Existing differs so update is triggered.
				getRuleResponseBody = buildGetRuleBody("block", "5")
				// setRule returns {"result":"failed"} with no validations when the UUID does not exist.
				updateResponseBody = `{"result":"failed"}`
			})

			It("sets Ready=False with NotFound reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("NotFound")),
					),
				))
			})
		})

		// --- Test 11d: ApplyFirewallRules fails after update ---
		Context("and ApplyFirewallRules fails after update", func() {
			BeforeEach(func() {
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				getRuleResponseBody = buildGetRuleBody("block", "5")
				updateResponseBody = resultSavedBody
				applyResponseBody = statusFailedBody
			})

			It("sets Ready=False with ApplyFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ApplyFailed")),
					),
				))
			})
		})

		// --- Test 11e: spec.Sequence triggers update when existing sequence differs ---
		Context("and spec.Sequence is set and differs from existing sequence", func() {
			var seq int32 = 100

			BeforeEach(func() {
				// Override the rule spec to include an explicit Sequence.
				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				rule.Spec.Sequence = &seq
				Expect(k8sClient.Update(ctx, rule)).To(Succeed())

				// Existing rule in OPNsense has sequence "5", spec wants "100" → update triggered.
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				// Same as existing in all fields except sequence is "5" not "100".
				getRuleResponseBody = buildGetRuleBody("pass", "5")
				updateResponseBody = resultSavedBody
				applyResponseBody = applyOKBody
			})

			It("triggers UpdateRule because of sequence drift and sets Ready=True", func() {
				// After update, getRule returns sequence "100".
				postUpdateBody := buildGetRuleBody("pass", "100")
				callCount := 0
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
						_, _ = fmt.Fprint(w, searchResponseBody)
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
						callCount++
						if callCount == 1 {
							_, _ = fmt.Fprint(w, getRuleResponseBody)
						} else {
							_, _ = fmt.Fprint(w, postUpdateBody)
						}
					case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/setRule/"):
						_, _ = fmt.Fprint(w, updateResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
						_, _ = fmt.Fprint(w, applyResponseBody)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.UUID).To(Equal(existingUUID))
				Expect(rule.Status.Sequence).To(Equal("100"))
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionTrue)),
					),
				))
			})
		})

		// --- Test 11f: GetFailed after UpdateRule succeeds ---
		Context("and GetRule fails after UpdateRule and Apply succeed", func() {
			BeforeEach(func() {
				searchResponseBody = fmt.Sprintf(`{"rows":[{"uuid":%q}]}`, existingUUID)
				getRuleResponseBody = buildGetRuleBody("block", "5")
				updateResponseBody = resultSavedBody
				applyResponseBody = applyOKBody
			})

			It("sets Ready=False with GetFailed reason", func() {
				callCount := 0
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
						_, _ = fmt.Fprint(w, searchResponseBody)
					case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
						callCount++
						if callCount == 1 {
							_, _ = fmt.Fprint(w, getRuleResponseBody) // drifted state
						} else {
							// Post-update GetRule fails with a 500.
							w.WriteHeader(http.StatusInternalServerError)
							_, _ = fmt.Fprint(w, `{"error":"internal"}`)
						}
					case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/setRule/"):
						_, _ = fmt.Fprint(w, updateResponseBody)
					case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
						_, _ = fmt.Fprint(w, applyResponseBody)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("GetFailed")),
					),
				))
			})
		})
	})

	// --- Test 17: deletion with buildOPNsenseClient failure ---
	Context("When the FirewallRule is being deleted but ConnectionRef is not found", func() {
		const ruleName = "fwr-delete-conn-missing"
		const ruleNS = "default"
		const testUUID = "22222222-2222-2222-2222-222222222222"

		BeforeEach(func() {
			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec("no-such-connection-for-delete"),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
			rule.Status.UUID = testUUID
			Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
		})

		AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

		It("sets Ready=False with ConnectionNotFound reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("ConnectionNotFound")),
				),
			))
		})
	})

	// --- Test 18: deletion with DeletionTimestamp set but firewallRuleFinalizer already gone ---
	Context("When the FirewallRule has a DeletionTimestamp but no firewallRuleFinalizer", func() {
		const ruleName = "fwr-delete-no-fwr-finalizer"
		const ruleNS = "default"

		BeforeEach(func() {
			// Create with a different finalizer so the CR persists after Delete
			// (Kubernetes keeps it alive until all finalizers are removed).
			// firewallRuleFinalizer is intentionally absent.
			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{"test.firewall.opnsense.io/cleanup"},
				},
				Spec: baseSpec("some-conn"),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
			// Delete sets DeletionTimestamp; the other finalizer keeps it alive.
			Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
		})

		AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

		It("returns empty result without error (early exit — firewallRuleFinalizer absent)", func() {
			result, err := reconcileRule(ruleName, ruleNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	// --- Test 19: LookupFailed when GetRule fails for a search result ---
	Context("When GetRule fails for a UUID returned by search", func() {
		const ruleName = "fwr-getrule-fail"
		const ruleNS = "default"
		const connName = "fwr-getrule-fail-conn"
		const secretName = "fwr-getrule-fail-creds"
		const matchUUID = "99999999-9999-9999-9999-999999999999"

		var server *httptest.Server
		var cleanupConn func()

		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/searchRule"):
					_, _ = fmt.Fprintf(w, `{"rows":[{"uuid":%q}]}`, matchUUID)
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/getRule/"):
					// Return an unexpected response shape to trigger ErrUnexpectedResponse.
					_, _ = fmt.Fprint(w, `{"rule":{"action":null,"direction":null}}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			cleanupConn = createReadyConnection(connName, secretName, server.URL)

			rule := &firewallv1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       ruleName,
					Namespace:  ruleNS,
					Finalizers: []string{firewallRuleFinalizer},
				},
				Spec: baseSpec(connName),
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())
		})

		AfterEach(func() {
			server.Close()
			deleteRuleCleanup(ruleName, ruleNS)
			cleanupConn()
		})

		It("sets Ready=False with LookupFailed reason", func() {
			_, err := reconcileRule(ruleName, ruleNS)
			Expect(err).To(HaveOccurred())

			rule := &firewallv1alpha1.FirewallRule{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
			Expect(rule.Status.Conditions).To(ContainElement(
				And(
					HaveField("Type", Equal("Ready")),
					HaveField("Status", Equal(metav1.ConditionFalse)),
					HaveField("Reason", Equal("LookupFailed")),
				),
			))
		})
	})

	// --- Tests 12–14: delete path ---
	Context("When the FirewallRule is being deleted", func() {
		const ruleNS = "default"
		const connName = "fwr-delete-conn"
		const secretName = "fwr-delete-creds"

		var server *httptest.Server
		var deleteResponseBody string
		var applyResponseBody string
		var cleanupConn func()

		BeforeEach(func() {
			applyResponseBody = applyOKBody

			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/filter/delRule/"):
					_, _ = fmt.Fprint(w, deleteResponseBody)
				case r.Method == http.MethodPost && r.URL.Path == applyFilterPath:
					_, _ = fmt.Fprint(w, applyResponseBody)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			cleanupConn = createReadyConnection(connName, secretName, server.URL)
		})

		AfterEach(func() {
			server.Close()
			cleanupConn()
		})

		// --- Test 12: deletion with UUID set — happy path ---
		Context("and status.UUID is set (happy path)", func() {
			const ruleName = "fwr-delete-ok"
			const testUUID = "dddddddd-dddd-dddd-dddd-dddddddddddd"

			BeforeEach(func() {
				deleteResponseBody = resultDeletedBody

				rule := &firewallv1alpha1.FirewallRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:       ruleName,
						Namespace:  ruleNS,
						Finalizers: []string{firewallRuleFinalizer},
					},
					Spec: baseSpec(connName),
				}
				Expect(k8sClient.Create(ctx, rule)).To(Succeed())
				rule.Status.UUID = testUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
				Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
			})

			AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

			It("calls DeleteRule and Apply, removes finalizer, CR is gone", func() {
				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, &firewallv1alpha1.FirewallRule{})
					return errors.IsNotFound(err)
				}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})

		// --- Test 13: deletion with UUID set but DeleteRule returns not found ---
		Context("and DeleteRule returns ErrFirewallRuleNotFound", func() {
			const ruleName = "fwr-delete-notfound"
			const testUUID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

			BeforeEach(func() {
				deleteResponseBody = `{"result":"not found"}`

				rule := &firewallv1alpha1.FirewallRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:       ruleName,
						Namespace:  ruleNS,
						Finalizers: []string{firewallRuleFinalizer},
					},
					Spec: baseSpec(connName),
				}
				Expect(k8sClient.Create(ctx, rule)).To(Succeed())
				rule.Status.UUID = testUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
				Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
			})

			AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

			It("treats it as already deleted, still calls Apply, removes finalizer", func() {
				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, &firewallv1alpha1.FirewallRule{})
					return errors.IsNotFound(err)
				}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})

		// --- Test 14: deletion with empty status.UUID ---
		Context("and status.UUID is empty", func() {
			const ruleName = "fwr-delete-no-uuid"

			BeforeEach(func() {
				rule := &firewallv1alpha1.FirewallRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:       ruleName,
						Namespace:  ruleNS,
						Finalizers: []string{firewallRuleFinalizer},
					},
					Spec: baseSpec(connName),
				}
				Expect(k8sClient.Create(ctx, rule)).To(Succeed())
				Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
			})

			AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

			It("removes the finalizer immediately without calling OPNsense", func() {
				result, err := reconcileRule(ruleName, ruleNS)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, &firewallv1alpha1.FirewallRule{})
					return errors.IsNotFound(err)
				}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})

		// --- Test 15: deletion, DeleteRule returns a generic error ---
		Context("and DeleteRule returns a generic error", func() {
			const ruleName = "fwr-delete-err"
			const testUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

			BeforeEach(func() {
				// "result":"error" is neither "deleted" nor "not found" → ErrUnexpectedResponse.
				deleteResponseBody = resultErrorBody

				rule := &firewallv1alpha1.FirewallRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:       ruleName,
						Namespace:  ruleNS,
						Finalizers: []string{firewallRuleFinalizer},
					},
					Spec: baseSpec(connName),
				}
				Expect(k8sClient.Create(ctx, rule)).To(Succeed())
				rule.Status.UUID = testUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
				Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
			})

			AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

			It("sets Ready=False with DeleteFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("DeleteFailed")),
					),
				))
			})
		})

		// --- Test 16: deletion, ApplyFirewallRules fails after delete ---
		Context("and ApplyFirewallRules fails during deletion", func() {
			const ruleName = "fwr-delete-apply-fail"
			const testUUID = "11111111-1111-1111-1111-111111111111"

			BeforeEach(func() {
				deleteResponseBody = resultDeletedBody
				applyResponseBody = statusFailedBody

				rule := &firewallv1alpha1.FirewallRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:       ruleName,
						Namespace:  ruleNS,
						Finalizers: []string{firewallRuleFinalizer},
					},
					Spec: baseSpec(connName),
				}
				Expect(k8sClient.Create(ctx, rule)).To(Succeed())
				rule.Status.UUID = testUUID
				Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
				Expect(k8sClient.Delete(ctx, rule)).To(Succeed())
			})

			AfterEach(func() { deleteRuleCleanup(ruleName, ruleNS) })

			It("sets Ready=False with ApplyFailed reason", func() {
				_, err := reconcileRule(ruleName, ruleNS)
				Expect(err).To(HaveOccurred())

				rule := &firewallv1alpha1.FirewallRule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: ruleName, Namespace: ruleNS}, rule)).To(Succeed())
				Expect(rule.Status.Conditions).To(ContainElement(
					And(
						HaveField("Type", Equal("Ready")),
						HaveField("Status", Equal(metav1.ConditionFalse)),
						HaveField("Reason", Equal("ApplyFailed")),
					),
				))
			})
		})
	})
})
