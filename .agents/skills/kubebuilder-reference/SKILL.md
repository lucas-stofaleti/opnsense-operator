---
name: kubebuilder-reference
description: Scaffold and extend Kubernetes operators with kubebuilder. Use when creating a new API type, controller, or webhook, converting to multi-group layout, or preparing a release.
---

# Kubebuilder Reference

## Core commands

### New API type + controller
```bash
kubebuilder create api --group <group> --version <version> --kind <Kind>
```

### New webhook (validation + defaulting)
```bash
kubebuilder create webhook --group <group> --version <version> --kind <Kind> \
  --defaulting --programmatic-validation
```

### Controller for existing Kubernetes or external types
```bash
# Core type (e.g. Pod)
kubebuilder create api --group core --version v1 --kind Pod \
  --controller=true --resource=false

# External type (e.g. cert-manager)
kubebuilder create api \
  --group cert-manager --version v1 --kind Certificate \
  --controller=true --resource=false \
  --external-api-path=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1 \
  --external-api-domain=io \
  --external-api-module=github.com/cert-manager/cert-manager
```

### Convert to multi-group layout
```bash
kubebuilder edit --multigroup=true
# Then:
#   mv api/<version>           api/<group>/
#   mv internal/controller/*.go  internal/controller/<group>/
# Update all import paths and PROJECT path entries.
# Add one more .. to envtest CRD paths in suite_test.go.
```

## After scaffolding or editing types

Always regenerate after editing `*_types.go` or kubebuilder markers:

```bash
make manifests  # Regenerates CRDs/RBAC
make generate   # Regenerates DeepCopy methods
```

## Gotchas

- **Never edit auto-generated files**: `config/crd/bases/*.yaml`, `config/rbac/role.yaml`, `**/zz_generated.*.go`, `PROJECT`. They are overwritten by `make manifests` / `make generate`.
- **Never remove scaffold markers**: `// +kubebuilder:scaffold:*` — kubebuilder injects code at these points.
- **Add custom RBAC via markers in controller files**, not by hand-editing `config/rbac/role.yaml`.
- **Always use `kubebuilder create`** to scaffold new files — never create controller or webhook files manually.
- When using `--force` on webhook scaffolding, backup custom logic first and restore after.

## Reference for deploy-image plugin

The deploy-image plugin generates a complete, best-practice controller (status conditions, finalizers, owner refs, events, idempotent reconciliation). Use it as a reference implementation:

```bash
kubebuilder create api --group example --version v1alpha1 --kind MyApp \
  --image=<your-image> --plugins=deploy-image.go.kubebuilder.io/v1-alpha
```

For the full markers cheat sheet (API type markers, field validation, RBAC, status conditions, controller patterns, webhooks), read [references/markers.md](references/markers.md).

For deployment workflow, distribution options (YAML bundle, Helm), and image publishing, read [references/deployment.md](references/deployment.md).
