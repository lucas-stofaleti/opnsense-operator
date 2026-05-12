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

// OPNsenseConnectionReference identifies the cluster-scoped OPNsenseConnection used by a resource.
type OPNsenseConnectionReference struct {
	// name is the name of the OPNsenseConnection resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// AliasSpec defines the desired state of Alias.
type AliasSpec struct {
	// connectionRef points to the OPNsenseConnection used to manage this alias.
	// +kubebuilder:validation:Required
	ConnectionRef OPNsenseConnectionReference `json:"connectionRef"`

	// name is the alias name in OPNsense.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// type is the OPNsense alias type, such as "host".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`

	// entries are the alias contents as separate items.
	// The controller joins them with newlines before sending them to OPNsense.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Entries []string `json:"entries"`

	// description is an optional free-form description stored in OPNsense.
	// +optional
	Description string `json:"description,omitempty"`

	// enabled controls whether the alias is enabled in OPNsense.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// AliasStatus defines the observed state of Alias.
type AliasStatus struct {
	// uuid is the OPNsense identifier for the managed alias.
	// +optional
	UUID string `json:"uuid,omitempty"`

	// observedGeneration records the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the Alias resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Alias",type=string,JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Connection",type=string,JSONPath=".spec.connectionRef.name"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// Alias is the Schema for the aliases API.
type Alias struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Alias
	// +required
	Spec AliasSpec `json:"spec"`

	// status defines the observed state of Alias
	// +optional
	Status AliasStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AliasList contains a list of Alias
type AliasList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Alias `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Alias{}, &AliasList{})
}
