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
5. Run `make lint` and fix every issue before moving on. A change is not complete
   if it introduces lint violations, even if all tests pass.
6. Refactor if needed, keeping tests green and lint clean.
7. Write or run the integration test to confirm it works against real OPNsense.

Never write implementation code before a failing test exists. Never skip the
"confirm it fails" step — a test that passes before implementation is a broken test.

### After implementing

- Run `make lint-fix` to auto-correct formatting issues.
- Run `make lint` and fix every reported issue. Zero issues is the only acceptable
  outcome. Do not use `//nolint` suppressions without explicit agreement from the user.
- Run the full unit test suite: `go test ./internal/...`
- Run the relevant integration test against real OPNsense:
  `go test ./internal/opnsense/... -tags integration -v`
- Run `make test` to confirm nothing is broken project-wide.

## OPNsense API

Load the `.agents/skills/opnsense-api` skill when working in `internal/opnsense/`.
It covers the curl verification workflow, `hack/opnsense-curl.sh` usage, and API gotchas.

**Core rule (always apply):** Never assume API behaviour — always verify with a real
request before writing tests or implementation.

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
- Use `defer func() { _ = resp.Body.Close() }()` immediately after every HTTP
  response check. The plain `defer resp.Body.Close()` form is flagged by `errcheck`
  because the error return value is silently dropped.


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

- **Never commit directly to `main`.** Always work on a separate branch and open
  a pull request.
- **Follow Conventional Commits.** Format: `<type>(<scope>): <description>`.
  Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`.
  Examples:
  - `feat(alias): add GetAliasByName method`
  - `fix(controller): handle stale UUID in status`
  - `test(alias): add integration test for delete`
  - `docs: update OPNsense API skill with reconfigure pattern`
- The description uses the imperative mood and starts lowercase: `add`, not
  `Added` or `Adding`.
- Keep commits small and focused. One logical change per commit.
- **Never include co-author attributions, AI references, or tool signatures in
  commits.** No `Co-authored-by: Claude`, no `Generated by`, no AI tool mentions
  of any kind. Commits are authored by the human developer.
- Do not commit generated files unless they are part of the intentional project
  output (CRD manifests are fine, binary artifacts are not).

## What agents must never do

- Never write implementation code before a failing test exists.
- Never assume OPNsense API behaviour — always verify with curl first.
- Never skip the integration test step.
- Never leave code that fails `make lint`. Run it after every change and fix all
  reported issues before considering the work done.
- Never commit directly to `main` — always use a branch.
- Never include AI attribution in commits or code comments.
- Never write a commit message that doesn't follow Conventional Commits format.
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

## Available skills

Load the appropriate skill for domain-specific reference:

- `.agents/skills/opnsense-api` — OPNsense API curl verification, gotchas. Load when working in `internal/opnsense/`.
- `.agents/skills/kubebuilder-reference` — kubebuilder CLI commands, markers cheat sheet, deployment workflow. Load when scaffolding new APIs, controllers, or preparing a release.

## Testing & Development

```bash
make test              # Run unit tests (uses envtest: real K8s API + etcd)
make run               # Run locally (uses current kubeconfig context)
```

Tests use **Ginkgo + Gomega** (BDD style). Check `suite_test.go` for setup.

## Logging

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
