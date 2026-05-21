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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
)

// buildHTTPClient constructs an *http.Client with TLS settings derived from the spec.
// Returns nil when no custom TLS is needed, which causes opnsense.NewClient to use http.DefaultClient.
func buildHTTPClient(ctx context.Context, cl client.Client, tlsSpec *firewallv1alpha1.TLSSpec) (*http.Client, error) {
	if tlsSpec == nil {
		return nil, nil
	}

	// A custom CA takes precedence over insecureSkipVerify.
	if tlsSpec.CASecretRef != nil {
		caKey := types.NamespacedName{
			Name:      tlsSpec.CASecretRef.Name,
			Namespace: tlsSpec.CASecretRef.Namespace,
		}
		caSecret := &corev1.Secret{}
		if err := cl.Get(ctx, caKey, caSecret); err != nil {
			return nil, fmt.Errorf("fetch CA Secret %s/%s: %w", caKey.Namespace, caKey.Name, err)
		}
		caCert, ok := caSecret.Data["ca.crt"]
		if !ok || len(caCert) == 0 {
			return nil, fmt.Errorf("CA Secret %s/%s must have a non-empty key 'ca.crt'", caKey.Namespace, caKey.Name)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from Secret %s/%s", caKey.Namespace, caKey.Name)
		}
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}, nil
	}

	if tlsSpec.InsecureSkipVerify {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}, nil
	}

	return nil, nil
}
