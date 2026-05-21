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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecretReference identifies a Kubernetes Secret by name and namespace.
type SecretReference struct {
	// name is the name of the Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// namespace is the namespace of the Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// CredentialsSpec holds the reference to the Secret containing the OPNsense API credentials.
// The referenced Secret must contain the keys "apiKey" and "apiSecret".
type CredentialsSpec struct {
	// secretRef is a reference to a Kubernetes Secret containing the OPNsense API credentials.
	// The Secret must have keys "apiKey" and "apiSecret".
	// +kubebuilder:validation:Required
	SecretRef SecretReference `json:"secretRef"`
}

// TLSSpec configures TLS for the OPNsense API connection.
type TLSSpec struct {
	// insecureSkipVerify disables TLS certificate verification.
	// Only use this in development environments with self-signed certificates.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// caSecretRef is a reference to a Secret containing a custom CA certificate bundle.
	// The Secret must have a key "ca.crt" with the PEM-encoded CA certificate.
	// If both insecureSkipVerify and caSecretRef are set, caSecretRef takes precedence.
	// +optional
	CASecretRef *SecretReference `json:"caSecretRef,omitempty"`
}

// OPNsenseConnectionSpec defines the desired state of OPNsenseConnection
type OPNsenseConnectionSpec struct {
	// url is the base URL of the OPNsense API (e.g. "https://opnsense.example.com").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// credentials holds the reference to the Secret containing the OPNsense API key and secret.
	// +kubebuilder:validation:Required
	Credentials CredentialsSpec `json:"credentials"`

	// tls configures TLS for the OPNsense API connection.
	// If omitted, standard TLS verification is used.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// OPNsenseConnectionStatus defines the observed state of OPNsenseConnection.
type OPNsenseConnectionStatus struct {
	// conditions represent the current state of the OPNsenseConnection.
	// The "Ready" condition is True when the connection has been validated successfully.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=".spec.url"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// OPNsenseConnection is the Schema for the opnsenseconnections API
type OPNsenseConnection struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of OPNsenseConnection
	// +required
	Spec OPNsenseConnectionSpec `json:"spec"`

	// status defines the observed state of OPNsenseConnection
	// +optional
	Status OPNsenseConnectionStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// OPNsenseConnectionList contains a list of OPNsenseConnection
type OPNsenseConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OPNsenseConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OPNsenseConnection{}, &OPNsenseConnectionList{})
}
