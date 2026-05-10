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
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
)

// statusServer starts an httptest.Server that returns the given HTTP status code
// for every request. Used to simulate OPNsense API responses.
func statusServer(code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(`{"metadata":{},"subsystems":{}}`))
		} else {
			_, _ = w.Write([]byte(`{"status":401,"message":"Authentication Failed"}`))
		}
	}))
}

// opnsenseConnectionFixture builds an OPNsenseConnection CR pointing at the given URL
// and referencing a Secret by name in the given namespace.
func opnsenseConnectionFixture(name, url, secretName, secretNamespace string) *firewallv1alpha1.OPNsenseConnection {
	return &firewallv1alpha1.OPNsenseConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: firewallv1alpha1.OPNsenseConnectionSpec{
			URL: url,
			Credentials: firewallv1alpha1.CredentialsSpec{
				SecretRef: firewallv1alpha1.SecretReference{
					Name:      secretName,
					Namespace: secretNamespace,
				},
			},
		},
	}
}

// credentialsSecret builds a Secret holding OPNsense API credentials.
func credentialsSecret(name, namespace, apiKey, apiSecret string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"apiKey":    []byte(apiKey),
			"apiSecret": []byte(apiSecret),
		},
	}
}

var _ = Describe("OPNsenseConnection Controller", func() {
	ctx := context.Background()

	// reconcileConnection is a helper that creates a fresh reconciler and triggers
	// a single reconciliation for the given OPNsenseConnection name.
	reconcileConnection := func(name string) (reconcile.Result, error) {
		r := &OPNsenseConnectionReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		return r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name},
		})
	}

	// readyCondition returns the Ready condition from an OPNsenseConnection, or nil.
	readyCondition := func(name string) *metav1.Condition {
		conn := &firewallv1alpha1.OPNsenseConnection{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, conn)).To(Succeed())
		c := meta.FindStatusCondition(conn.Status.Conditions, "Ready")
		return c
	}

	Context("When the Secret exists with valid credentials and OPNsense is reachable", func() {
		const connName = "conn-valid"
		const secretName = "opnsense-creds-valid"
		const secretNS = "default"

		var server *httptest.Server

		BeforeEach(func() {
			server = statusServer(http.StatusOK)

			By("creating the credentials Secret")
			secret := credentialsSecret(secretName, secretNS, "key", "secret")
			err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating the OPNsenseConnection CR")
			conn := opnsenseConnectionFixture(connName, server.URL, secretName, secretNS)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: connName}, &firewallv1alpha1.OPNsenseConnection{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			}
		})

		AfterEach(func() {
			server.Close()

			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}

			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret); err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("sets Ready=True and requeues after 1 minute", func() {
			result, err := reconcileConnection(connName)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))

			cond := readyCondition(connName)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("ConnectionVerified"))
		})
	})

	Context("When the referenced Secret does not exist", func() {
		const connName = "conn-no-secret"

		BeforeEach(func() {
			By("creating the OPNsenseConnection CR with a missing Secret reference")
			conn := opnsenseConnectionFixture(connName, "http://irrelevant", "does-not-exist", "default")
			err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, &firewallv1alpha1.OPNsenseConnection{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			}
		})

		AfterEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}
		})

		It("sets Ready=False with reason SecretNotFound", func() {
			_, err := reconcileConnection(connName)
			Expect(err).To(HaveOccurred())

			cond := readyCondition(connName)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("SecretNotFound"))
		})
	})

	Context("When the Secret is missing required credential keys", func() {
		const connName = "conn-bad-secret"
		const secretName = "opnsense-creds-empty"
		const secretNS = "default"

		BeforeEach(func() {
			By("creating a Secret with no credential keys")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNS},
				Data:       map[string][]byte{},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating the OPNsenseConnection CR")
			conn := opnsenseConnectionFixture(connName, "http://irrelevant", secretName, secretNS)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: connName}, &firewallv1alpha1.OPNsenseConnection{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			}
		})

		AfterEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret); err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("sets Ready=False with reason InvalidCredentials", func() {
			_, err := reconcileConnection(connName)
			Expect(err).To(HaveOccurred())

			cond := readyCondition(connName)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("InvalidCredentials"))
		})
	})

	Context("When OPNsense returns an authentication error", func() {
		const connName = "conn-auth-fail"
		const secretName = "opnsense-creds-wrong"
		const secretNS = "default"

		var server *httptest.Server

		BeforeEach(func() {
			server = statusServer(http.StatusUnauthorized)

			By("creating the credentials Secret with wrong credentials")
			secret := credentialsSecret(secretName, secretNS, "wrongkey", "wrongsecret")
			err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating the OPNsenseConnection CR")
			conn := opnsenseConnectionFixture(connName, server.URL, secretName, secretNS)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: connName}, &firewallv1alpha1.OPNsenseConnection{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			}
		})

		AfterEach(func() {
			server.Close()

			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret); err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("sets Ready=False with reason ConnectionFailed", func() {
			_, err := reconcileConnection(connName)
			Expect(err).To(HaveOccurred())

			cond := readyCondition(connName)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("ConnectionFailed"))
		})
	})

	Context("When OPNsense is unreachable", func() {
		const connName = "conn-unreachable"
		const secretName = "opnsense-creds-unreachable"
		const secretNS = "default"

		BeforeEach(func() {
			By("creating the credentials Secret")
			secret := credentialsSecret(secretName, secretNS, "key", "secret")
			err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating the OPNsenseConnection CR pointing at a non-listening address")
			// Use a URL that will produce a connection refused error.
			conn := opnsenseConnectionFixture(connName, "http://127.0.0.1:1", secretName, secretNS)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: connName}, &firewallv1alpha1.OPNsenseConnection{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, conn)).To(Succeed())
			}
		})

		AfterEach(func() {
			conn := &firewallv1alpha1.OPNsenseConnection{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: connName}, conn); err == nil {
				Expect(k8sClient.Delete(ctx, conn)).To(Succeed())
			}
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNS}, secret); err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("sets Ready=False with reason ConnectionFailed", func() {
			_, err := reconcileConnection(connName)
			Expect(err).To(HaveOccurred())

			cond := readyCondition(connName)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("ConnectionFailed"))
		})
	})
})
