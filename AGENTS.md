# opnsense-operator - AI Agent Guide

This file defines how AI agents should behave when contributing to this project.
Read it fully before making any changes.

## About this project

This is a Kubernetes operator for managing OPNsense firewall resources, built with
kubebuilder and controller-runtime. The primary maintainer has strong infrastructure
knowledge but is learning Go and operator development. This context shapes everything
below — explanations matter as much as the code itself.

## Communication and collaboration

- **Always discuss before implementing.** Before writing any code, explain what you
  intend to do and why. Ask the user if they agree with the approach.
- **Ask questions.** If something is unclear — a requirement, a preference, an edge
  case — ask rather than assume. One focused question is better than three at once.
- **Validate hypotheses.** If you are not sure how something behaves (an API, a
  library, a Kubernetes concept), say so and suggest how to verify it before
  proceeding.
- **Split problems into small chunks.** Each chunk should be agreed and validated
  by the user before moving to the next. Never implement multiple steps ahead.
- **Explain your ideas.** The user is learning. Always explain what you are doing,
  why you chose that approach, and what the alternatives were. Do this in plain
  language, not just in code comments.
- **Explain code line by line when introducing new concepts.** If a function
  introduces a pattern the user has not seen before, walk through it explicitly.

## Development workflow

### Before writing any code

1. Discuss the requirement with the user and agree on the approach.
2. Identify edge cases. Ask yourself: what can go wrong? How could a user misuse
   this? What happens if the external system behaves unexpectedly?
3. If the change involves the OPNsense API, verify the real behaviour first (see
   the OPNsense API section below). Never assume how the API behaves.

### Test-driven development

This project follows strict TDD. The order is non-negotiable:

1. Write the failing test first.
2. Run it and confirm it fails for the right reason.
3. Write the minimum code to make it pass — nothing more.
4. Run the tests and confirm they pass.
5. Refactor if needed, keeping tests green.
6. Write or run the integration test to confirm it works against real OPNsense.

Never write implementation code before a failing test exists. Never skip the
"confirm it fails" step — a test that passes before implementation is a broken test.

### After implementing

- Run the full unit test suite: `go test ./internal/...`
- Run the relevant integration test against real OPNsense:
  `go test ./internal/opnsense/... -tags integration -v`
- Run `make test` to confirm nothing is broken project-wide.

## OPNsense API

- **Never assume how the API behaves.** Before writing a test or implementation
  for any OPNsense API endpoint, verify its real behaviour using curl against the
  local OPNsense VM.
- Use `hack/opnsense-curl.sh` for these checks instead of hand-writing curl
  commands each time. The script expects `OPNSENSE_BASE_URL`,
  `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET`. For self-signed TLS, set
  `OPNSENSE_INSECURE=true`. If you have a trusted CA bundle, set
  `OPNSENSE_CA_CERT` instead. The helper supports GET/POST/PUT/DELETE style
  checks, inline JSON bodies, body files, stdin, custom headers, query strings,
  and pass-through curl flags after `--`.
- Check both the happy path and failure cases. OPNsense often returns HTTP 200
  with `{"result": "failed"}` instead of a 4xx status code — this matters for
  error handling.
- Use the official OPNsense API documentation to complement what you observe.
  Documentation alone is not enough — always verify with a real request.
- Document the curl command and real response in a comment above the test, so the
  reasoning is clear to anyone reading it later.

Example approach before implementing a new method:
```bash
# Verify the real response shape before writing the test
hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/test
# {"uuid":"c6b50d57-b441-4217-a2d1-b81313887fdc"}

# Verify a POST endpoint with JSON
hack/opnsense-curl.sh -X POST \
  -d '{"alias":{"name":"test","type":"host","content":"192.0.2.10"}}' \
  /api/firewall/alias/addItem
```

## Testing strategy

This project uses three layers of tests. Understand which layer you are in.

### Unit tests (`internal/opnsense/*_test.go`)
- Use `httptest.NewServer` to mock the HTTP layer.
- The mock must reflect the real OPNsense response shape, verified by curl first.
- Test the happy path and all known failure cases.
- No build tag — these always run.
- Run with: `go test ./internal/...`

### Integration tests (`//go:build integration`)
- Run against the real OPNsense VM. No mocks.
- Required after implementing any new client method.
- Credentials come from environment variables — never hardcoded.
- Run with: `go test ./internal/opnsense/... -tags integration -v`
- These are mandatory before considering a feature complete.

### Controller tests (`internal/controller/`)
- Use envtest (a real Kubernetes API server, no mocks).
- Run as part of `make test`.

### Coverage expectations
- Do not optimize for coverage percentage alone. Optimize for behavior coverage:
  happy path, known failure paths, transport errors, unexpected response shapes,
  not-found behavior, validation failures, and delete/update edge cases.
- For any changed package, aim for at least 80% statement coverage.
- For critical OPNsense client and controller reconciliation paths, aim for 90%+
  coverage of the touched functions and branches.
- Coverage percentage is a floor, not the goal. A change is not complete if
  meaningful branches are still untested, even if the package-level percentage
  looks acceptable.

## Edge cases

Always think through these before implementing:

- What if OPNsense is unreachable?
- What if OPNsense returns an unexpected response shape?
- What if the resource was deleted in OPNsense but still exists in Kubernetes?
- What if the operator restarts mid-reconcile?
- What if the user applies a CR with a name that already exists in OPNsense?
- What if the UUID stored in status is stale?
- What if the user deletes a CR before it was ever successfully created?

Document how each edge case is handled, either in comments or in the discussion
with the user before implementing.


## Go standards

- Follow standard Go conventions: `gofmt`, `go vet`, meaningful variable names.
- Keep functions small and focused on one responsibility.
- Return errors — never swallow them silently with `_` unless there is an explicit
  reason, which must be documented with a comment.
- Use `errors.Is` and sentinel errors for distinguishing error types. Never compare
  error strings.
- Use `context.Context` as the first argument in every function that makes a
  network call or could be cancelled.
- Prefer explicit over clever. This codebase is a learning environment — clarity
  beats brevity.
- Use `defer resp.Body.Close()` immediately after every HTTP response check.


## Kubernetes and kubebuilder standards

- Follow the Kubernetes API conventions for status conditions: use `metav1.Condition`
  with standard `True/False/Unknown` values.
- Always use finalizers when the operator manages external resources that need
  cleanup on deletion.
- Store external resource identifiers (like OPNsense UUIDs) in `.status`, not
  `.spec`. Spec is desired state, status is observed state.
- Use `ObservedGeneration` in status to signal whether the controller has processed
  the latest version of the spec.
- Set `Ready=False` with a descriptive message on any error before returning it.
  Never leave a stale `Ready=True` when something is broken.
- Follow controller-runtime patterns: return `ctrl.Result{}` on success,
  `ctrl.Result{Requeue: true}` for immediate retry, and
  `ctrl.Result{RequeueAfter: duration}` for periodic reconciliation.

## Git and commits

- **Never include co-author attributions, AI references, or tool signatures in
  commits.** No `Co-authored-by: Claude`, no `Generated by`, no AI tool mentions
  of any kind. Commits are authored by the human developer.
- Write commit messages in the imperative mood: `Add GetAliasByName method`, not
  `Added` or `Adding`.
- Keep commits small and focused. One logical change per commit.
- Do not commit generated files unless they are part of the intentional project
  output (CRD manifests are fine, binary artifacts are not).

## What agents must never do

- Never write implementation code before a failing test exists.
- Never assume OPNsense API behaviour — always verify with curl first.
- Never skip the integration test step.
- Never include AI attribution in commits or code comments.
- Never implement more than the agreed chunk without checking with the user first.
- Never silently swallow errors.
- Never hardcode credentials, IPs, or environment-specific values in code or tests.
- Never introduce a new dependency without discussing it with the user first.

## Project Structure

**Single-group layout (default):**
```
cmd/main.go                    Manager entry (registers controllers/webhooks)
api/<version>/*_types.go       CRD schemas (+kubebuilder markers)
api/<version>/zz_generated.*   Auto-generated (DO NOT EDIT)
internal/controller/*          Reconciliation logic
internal/webhook/*             Validation/defaulting (if present)
config/crd/bases/*             Generated CRDs (DO NOT EDIT)
config/rbac/role.yaml          Generated RBAC (DO NOT EDIT)
config/samples/*               Example CRs (edit these)
Makefile                       Build/test/deploy commands
PROJECT                        Kubebuilder metadata Auto-generated (DO NOT EDIT)
```

**Multi-group layout** (for projects with multiple API groups):
```
api/<group>/<version>/*_types.go       CRD schemas by group
internal/controller/<group>/*          Controllers by group
internal/webhook/<group>/<version>/*   Webhooks by group and version (if present)
```

Multi-group layout organizes APIs by group name (e.g., `batch`, `apps`). Check the `PROJECT` file for `multigroup: true`.

**To convert to multi-group layout:**
1. Run: `kubebuilder edit --multigroup=true`
2. Move APIs: `mkdir -p api/<group> && mv api/<version> api/<group>/`
3. Move controllers: `mkdir -p internal/controller/<group> && mv internal/controller/*.go internal/controller/<group>/`
4. Move webhooks (if present): `mkdir -p internal/webhook/<group> && mv internal/webhook/<version> internal/webhook/<group>/`
5. Update import paths in all files
6. Fix `path` in `PROJECT` file for each resource
7. Update test suite CRD paths (add one more `..` to relative paths)

## Critical Rules

### Never Edit These (Auto-Generated)
- `config/crd/bases/*.yaml` - from `make manifests`
- `config/rbac/role.yaml` - from `make manifests`
- `config/webhook/manifests.yaml` - from `make manifests`
- `**/zz_generated.*.go` - from `make generate`
- `PROJECT` - from `kubebuilder [OPTIONS]`

### Never Remove Scaffold Markers
Do NOT delete `// +kubebuilder:scaffold:*` comments. CLI injects code at these markers.

### Keep Project Structure
Do not move files around. The CLI expects files in specific locations.

### Always Use CLI Commands
Always use `kubebuilder create api` and `kubebuilder create webhook` to scaffold. Do NOT create files manually.

### E2E Tests Require an Isolated Kind Cluster
The e2e tests are designed to validate the solution in an isolated environment (similar to GitHub Actions CI).
Ensure you run them against a dedicated [Kind](https://kind.sigs.k8s.io/) cluster (not your “real” dev/prod cluster).

## After Making Changes

**After editing `*_types.go` or markers:**
```
make manifests  # Regenerate CRDs/RBAC from markers
make generate   # Regenerate DeepCopy methods
```

**After editing `*.go` files:**
```
make lint-fix   # Auto-fix code style
make test       # Run unit tests
```

## CLI Commands Cheat Sheet

### Create API (your own types)
```bash
kubebuilder create api --group <group> --version <version> --kind <Kind>
```

### Deploy Image Plugin (scaffold to deploy/manage ANY container image)

Generate a controller that deploys and manages a container image (nginx, redis, memcached, your app, etc.):

```bash
# Example: deploying memcached
kubebuilder create api --group example.com --version v1alpha1 --kind Memcached \
  --image=memcached:alpine \
  --plugins=deploy-image.go.kubebuilder.io/v1-alpha
```

Scaffolds good-practice code: reconciliation logic, status conditions, finalizers, RBAC. Use as a reference implementation.


### Create Webhooks
```bash
# Validation + defaulting
kubebuilder create webhook --group <group> --version <version> --kind <Kind> \
  --defaulting --programmatic-validation

# Conversion webhook (for multi-version APIs)
kubebuilder create webhook --group <group> --version v1 --kind <Kind> \
  --conversion --spoke v2
```

### Controller for Core Kubernetes Types
```bash
# Watch Pods
kubebuilder create api --group core --version v1 --kind Pod \
  --controller=true --resource=false

# Watch Deployments
kubebuilder create api --group apps --version v1 --kind Deployment \
  --controller=true --resource=false
```

### Controller for External Types (e.g., from other operators)

Watch resources from external APIs (cert-manager, Argo CD, Istio, etc.):

```bash
# Example: watching cert-manager Certificate resources
kubebuilder create api \
  --group cert-manager --version v1 --kind Certificate \
  --controller=true --resource=false \
  --external-api-path=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1 \
  --external-api-domain=io \
  --external-api-module=github.com/cert-manager/cert-manager
```

**Note:** Use `--external-api-module=<module>@<version>` only if you need a specific version. Otherwise, omit `@<version>` to use what's in go.mod.

### Webhook for External Types

```bash
# Example: validating external resources
kubebuilder create webhook \
  --group cert-manager --version v1 --kind Issuer \
  --defaulting \
  --external-api-path=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1 \
  --external-api-domain=io \
  --external-api-module=github.com/cert-manager/cert-manager
```

## Testing & Development

```bash
make test              # Run unit tests (uses envtest: real K8s API + etcd)
make run               # Run locally (uses current kubeconfig context)
```

Tests use **Ginkgo + Gomega** (BDD style). Check `suite_test.go` for setup.

## Deployment Workflow

```bash
# 1. Regenerate manifests
make manifests generate

# 2. Build & deploy
export IMG=<registry>/<project>:tag
make docker-build docker-push IMG=$IMG  # Or: kind load docker-image $IMG --name <cluster>
make deploy IMG=$IMG

# 3. Test
kubectl apply -k config/samples/

# 4. Debug
kubectl logs -n <project>-system deployment/<project>-controller-manager -c manager -f
```

### API Design

**Key markers for** `api/<version>/*_types.go`:

```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"

// On fields:
// +kubebuilder:validation:Required
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:MaxLength=100
// +kubebuilder:validation:Pattern="^[a-z]+$"
// +kubebuilder:default="value"
```

- **Use** `metav1.Condition` for status (not custom string fields)
- **Use predefined types**: `metav1.Time` instead of `string` for dates
- **Follow K8s API conventions**: Standard field names (`spec`, `status`, `metadata`)

### Controller Design

**RBAC markers in** `internal/controller/*_controller.go`:

```go
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/finalizers,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
```

**Implementation rules:**
- **Idempotent reconciliation**: Safe to run multiple times
- **Re-fetch before updates**: `r.Get(ctx, req.NamespacedName, obj)` before `r.Update` to avoid conflicts
- **Structured logging**: `log := log.FromContext(ctx); log.Info("msg", "key", val)`
- **Owner references**: Enable automatic garbage collection (`SetControllerReference`)
- **Watch secondary resources**: Use `.Owns()` or `.Watches()`, not just `RequeueAfter`
- **Finalizers**: Clean up external resources (buckets, VMs, DNS entries)

### Logging

**Follow Kubernetes logging message style guidelines:**

- Start from a capital letter
- Do not end the message with a period
- Active voice: subject present (`"Deployment could not create Pod"`) or omitted (`"Could not create Pod"`)
- Past tense: `"Could not delete Pod"` not `"Cannot delete Pod"`
- Specify object type: `"Deleted Pod"` not `"Deleted"`
- Balanced key-value pairs

```go
log.Info("Starting reconciliation")
log.Info("Created Deployment", "name", deploy.Name)
log.Error(err, "Failed to create Pod", "name", name)
```

**Reference:** https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#message-style-guidelines

### Webhooks
- **Create all types together**: `--defaulting --programmatic-validation --conversion`
- **When`--force`is used**: Backup custom logic first, then restore after scaffolding
- **For multi-version APIs**: Use hub-and-spoke pattern (`--conversion --spoke v2`)
  - Hub version: Usually oldest stable version (v1)
  - Spoke versions: Newer versions that convert to/from hub (v2, v3)
  - Example: `--group crew --version v1 --kind Captain --conversion --spoke v2` (v1 is hub, v2 is spoke)

### Learning from Examples

The **deploy-image plugin** scaffolds a complete controller following good practices. Use it as a reference implementation:

```bash
kubebuilder create api --group example --version v1alpha1 --kind MyApp \
  --image=<your-image> --plugins=deploy-image.go.kubebuilder.io/v1-alpha
```

Generated code includes: status conditions (`metav1.Condition`), finalizers, owner references, events, idempotent reconciliation.

## Distribution Options

### Option 1: YAML Bundle (Kustomize)

```bash
# Generate dist/install.yaml from Kustomize manifests
make build-installer IMG=<registry>/<project>:tag
```

**Key points:**
- The `dist/install.yaml` is generated from Kustomize manifests (CRDs, RBAC, Deployment)
- Commit this file to your repository for easy distribution
- Users only need `kubectl` to install (no additional tools required)

**Example:** Users install with a single command:
```bash
kubectl apply -f https://raw.githubusercontent.com/<org>/<repo>/<tag>/dist/install.yaml
```

### Option 2: Helm Chart

```bash
kubebuilder edit --plugins=helm/v2-alpha                      # Generates dist/chart/ (default)
kubebuilder edit --plugins=helm/v2-alpha --output-dir=charts  # Generates charts/chart/
```

**For development:**
```bash
make helm-deploy IMG=<registry>/<project>:<tag>          # Deploy manager via Helm
make helm-deploy IMG=$IMG HELM_EXTRA_ARGS="--set ..."    # Deploy with custom values
make helm-status                                         # Show release status
make helm-uninstall                                      # Remove release
make helm-history                                        # View release history
make helm-rollback                                       # Rollback to previous version
```

**For end users/production:**
```bash
helm install my-release ./<output-dir>/chart/ --namespace <ns> --create-namespace
```

**Important:** If you add webhooks or modify manifests after initial chart generation:
1. Backup any customizations in `<output-dir>/chart/values.yaml` and `<output-dir>/chart/manager/manager.yaml`
2. Re-run: `kubebuilder edit --plugins=helm/v2-alpha --force` (use same `--output-dir` if customized)
3. Manually restore your custom values from the backup

### Publish Container Image

```bash
export IMG=<registry>/<project>:<version>
make docker-build docker-push IMG=$IMG
```

## References

### Essential Reading
- **Kubebuilder Book**: https://book.kubebuilder.io (comprehensive guide)
- **controller-runtime FAQ**: https://github.com/kubernetes-sigs/controller-runtime/blob/main/FAQ.md (common patterns and questions)
- **Good Practices**: https://book.kubebuilder.io/reference/good-practices.html (why reconciliation is idempotent, status conditions, etc.)
- **Logging Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#message-style-guidelines (message style, verbosity levels)

### API Design & Implementation
- **API Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- **Operator Pattern**: https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
- **Markers Reference**: https://book.kubebuilder.io/reference/markers.html

### Tools & Libraries
- **controller-runtime**: https://github.com/kubernetes-sigs/controller-runtime
- **controller-tools**: https://github.com/kubernetes-sigs/controller-tools
- **Kubebuilder Repo**: https://github.com/kubernetes-sigs/kubebuilder
