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

// FirewallRuleEndpoint defines a traffic endpoint (source or destination) for a firewall rule.
type FirewallRuleEndpoint struct {
	// net is the network address or alias to match (e.g. "any", "192.168.1.0/24", "myalias").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Net string `json:"net"`

	// not inverts the match — traffic NOT from/to this net.
	// +optional
	Not bool `json:"not,omitempty"`

	// port is the port or port range (e.g. "443", "8080:8090"). Empty means any port.
	// +optional
	Port string `json:"port,omitempty"`
}

// FirewallRuleSpec defines the desired state of FirewallRule.
type FirewallRuleSpec struct {
	// connectionRef points to the OPNsenseConnection used to manage this rule.
	// +kubebuilder:validation:Required
	ConnectionRef OPNsenseConnectionReference `json:"connectionRef"`

	// enabled controls whether the rule is active in OPNsense.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// action defines what to do with matching traffic.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=pass;block;reject
	Action string `json:"action"`

	// direction is the traffic direction to match.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=in;out;any
	Direction string `json:"direction"`

	// interface is the OPNsense interface name (e.g. "lan", "wan").
	// Leave empty for a floating rule that applies to all interfaces.
	// +optional
	Interface string `json:"interface,omitempty"`

	// ipProtocol is the IP version to match.
	// +kubebuilder:default=inet
	// +kubebuilder:validation:Enum=inet;inet6;inet46
	// +optional
	IPProtocol string `json:"ipProtocol,omitempty"`

	// protocol is the transport protocol to match (e.g. "any", "TCP", "UDP", "ICMP").
	// No enum — OPNsense validates the value.
	// +kubebuilder:default=any
	// +optional
	Protocol string `json:"protocol,omitempty"`

	// source defines the traffic source match criteria.
	// +kubebuilder:validation:Required
	Source FirewallRuleEndpoint `json:"source"`

	// destination defines the traffic destination match criteria.
	// +kubebuilder:validation:Required
	Destination FirewallRuleEndpoint `json:"destination"`

	// sequence is the rule ordering position in OPNsense.
	// If omitted, OPNsense assigns a position automatically.
	// +optional
	Sequence *int32 `json:"sequence,omitempty"`

	// quick stops processing further rules when this rule matches.
	// +kubebuilder:default=true
	// +optional
	Quick bool `json:"quick,omitempty"`

	// log enables logging for traffic matched by this rule.
	// +optional
	Log bool `json:"log,omitempty"`

	// description is a human-readable description stored in OPNsense.
	// The controller appends a managed suffix automatically — do not include it here.
	// +optional
	Description string `json:"description,omitempty"`
}

// FirewallRuleStatus defines the observed state of FirewallRule.
type FirewallRuleStatus struct {
	// uuid is the OPNsense identifier for the managed rule.
	// +optional
	UUID string `json:"uuid,omitempty"`

	// sequence is the rule ordering position observed in OPNsense.
	// Populated by the controller after create or update.
	// +optional
	Sequence string `json:"sequence,omitempty"`

	// observedGeneration records the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the FirewallRule resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fwr
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Sequence",type=string,JSONPath=".status.sequence"
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=".spec.action"
// +kubebuilder:printcolumn:name="Direction",type=string,JSONPath=".spec.direction",priority=1
// +kubebuilder:printcolumn:name="Interface",type=string,JSONPath=".spec.interface"
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=".spec.source.net",priority=1
// +kubebuilder:printcolumn:name="Destination",type=string,JSONPath=".spec.destination.net",priority=1
// +kubebuilder:printcolumn:name="Connection",type=string,JSONPath=".spec.connectionRef.name"
// +kubebuilder:printcolumn:name="UUID",type=string,JSONPath=".status.uuid",priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// FirewallRule is the Schema for the firewallrules API.
type FirewallRule struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of FirewallRule
	// +required
	Spec FirewallRuleSpec `json:"spec"`

	// status defines the observed state of FirewallRule
	// +optional
	Status FirewallRuleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// FirewallRuleList contains a list of FirewallRule
type FirewallRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []FirewallRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FirewallRule{}, &FirewallRuleList{})
}
