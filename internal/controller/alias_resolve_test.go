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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	firewallv1alpha1 "github.com/lucas-stofaleti/opnsense-operator/api/v1alpha1"
	"github.com/lucas-stofaleti/opnsense-operator/internal/opnsense"
)

var _ = Describe("resolveExternalAlias", func() {
	const (
		// staleUUID simulates a UUID stored in status that no longer exists in OPNsense.
		staleUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		// resolvedUUID simulates the UUID returned from a name lookup or a fresh GetAlias.
		resolvedUUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		specName     = "allow_dns"
	)

	var (
		resolveCtx          context.Context
		server              *httptest.Server
		r                   *AliasReconciler
		getAliasHandler     func(http.ResponseWriter, *http.Request)
		getAliasUUIDHandler func(http.ResponseWriter, *http.Request)
	)

	// aliasFoundBody returns a valid GetAlias (export) response containing the given uuid.
	// curl /api/firewall/alias/export?ids=<uuid>
	// {"aliases":{"alias":{"<uuid>":{"enabled":"1","name":"allow_dns","type":"host","content":"198.51.100.10","description":"test"}}}}
	aliasFoundBody := func(uuid string) string {
		return fmt.Sprintf(
			`{"aliases":{"alias":{%q:{"enabled":"1","name":%q,"type":"host","content":"198.51.100.10","description":"test"}}}}`,
			uuid, specName,
		)
	}

	// aliasNotFoundBody is the export response when the UUID does not exist.
	// curl /api/firewall/alias/export?ids=<unknown-uuid>
	// {"aliases":{"alias":[]}}
	const aliasNotFoundBody = `{"aliases":{"alias":[]}}`

	// uuidFoundBody returns a valid GetAliasUUIDByName response.
	// curl /api/firewall/alias/getAliasUUID/allow_dns
	// {"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
	uuidFoundBody := func(uuid string) string {
		return fmt.Sprintf(`{"uuid":%q}`, uuid)
	}

	// uuidNotFoundBody is the response when no alias with that name exists.
	// curl /api/firewall/alias/getAliasUUID/unknown
	// []
	const uuidNotFoundBody = `[]`

	BeforeEach(func() {
		resolveCtx = context.Background()
		r = &AliasReconciler{}

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch {
			case strings.HasPrefix(req.URL.Path, "/api/firewall/alias/export"):
				getAliasHandler(w, req)
			case strings.HasPrefix(req.URL.Path, "/api/firewall/alias/getAliasUUID"):
				getAliasUUIDHandler(w, req)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	})

	AfterEach(func() {
		server.Close()
	})

	makeClient := func() *opnsense.Client {
		return opnsense.NewClient(server.URL, "key", "secret", nil)
	}

	makeAlias := func(uuid string) *firewallv1alpha1.Alias {
		return &firewallv1alpha1.Alias{
			Spec:   firewallv1alpha1.AliasSpec{Name: specName},
			Status: firewallv1alpha1.AliasStatus{UUID: uuid},
		}
	}

	Context("When status.uuid is set", func() {
		Context("and GetAlias returns the alias", func() {
			BeforeEach(func() {
				getAliasHandler = func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, aliasFoundBody(staleUUID))
				}
			})

			It("returns the uuid and alias without calling GetAliasUUIDByName", func() {
				uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(staleUUID))
				Expect(err).NotTo(HaveOccurred())
				Expect(uuid).To(Equal(staleUUID))
				Expect(existing).NotTo(BeNil())
				Expect(existing.Name).To(Equal(specName))
			})
		})

		Context("and GetAlias returns not found (stale UUID)", func() {
			BeforeEach(func() {
				// First GetAlias call (stale UUID) → not found.
				// Second GetAlias call (resolved UUID) → found.
				getAliasHandler = func(w http.ResponseWriter, req *http.Request) {
					if strings.Contains(req.URL.RawQuery, staleUUID) {
						fmt.Fprint(w, aliasNotFoundBody)
					} else {
						fmt.Fprint(w, aliasFoundBody(resolvedUUID))
					}
				}
			})

			Context("and GetAliasUUIDByName finds the alias by name", func() {
				BeforeEach(func() {
					getAliasUUIDHandler = func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprint(w, uuidFoundBody(resolvedUUID))
					}
				})

				It("falls back to name lookup and returns the resolved uuid and alias", func() {
					uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(staleUUID))
					Expect(err).NotTo(HaveOccurred())
					Expect(uuid).To(Equal(resolvedUUID))
					Expect(existing).NotTo(BeNil())
					Expect(existing.Name).To(Equal(specName))
				})
			})

			Context("and GetAliasUUIDByName returns not found", func() {
				BeforeEach(func() {
					getAliasUUIDHandler = func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprint(w, uuidNotFoundBody)
					}
				})

				It("returns empty uuid and nil alias (alias is missing externally)", func() {
					uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(staleUUID))
					Expect(err).NotTo(HaveOccurred())
					Expect(uuid).To(BeEmpty())
					Expect(existing).To(BeNil())
				})
			})
		})

		Context("and GetAlias returns an unexpected error", func() {
			BeforeEach(func() {
				getAliasHandler = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "internal error")
				}
			})

			It("returns the error", func() {
				uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(staleUUID))
				Expect(err).To(HaveOccurred())
				Expect(uuid).To(BeEmpty())
				Expect(existing).To(BeNil())
			})
		})
	})

	Context("When status.uuid is empty", func() {
		Context("and GetAliasUUIDByName finds the alias", func() {
			BeforeEach(func() {
				getAliasUUIDHandler = func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, uuidFoundBody(resolvedUUID))
				}
				getAliasHandler = func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, aliasFoundBody(resolvedUUID))
				}
			})

			It("returns the uuid and alias", func() {
				uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(uuid).To(Equal(resolvedUUID))
				Expect(existing).NotTo(BeNil())
				Expect(existing.Name).To(Equal(specName))
			})
		})

		Context("and GetAliasUUIDByName returns not found", func() {
			BeforeEach(func() {
				getAliasUUIDHandler = func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, uuidNotFoundBody)
				}
			})

			It("returns empty uuid and nil alias (alias does not exist)", func() {
				uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(""))
				Expect(err).NotTo(HaveOccurred())
				Expect(uuid).To(BeEmpty())
				Expect(existing).To(BeNil())
			})
		})

		Context("and GetAliasUUIDByName returns an unexpected error", func() {
			BeforeEach(func() {
				getAliasUUIDHandler = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "internal error")
				}
			})

			It("returns the error", func() {
				uuid, existing, err := r.resolveExternalAlias(resolveCtx, makeClient(), makeAlias(""))
				Expect(err).To(HaveOccurred())
				Expect(uuid).To(BeEmpty())
				Expect(existing).To(BeNil())
			})
		})
	})
})
