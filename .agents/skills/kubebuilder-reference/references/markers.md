# Kubebuilder Markers Reference

## API type markers (`api/<version>/*_types.go`)

```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
```

### Field validation markers

```go
// +kubebuilder:validation:Required
// +kubebuilder:validation:Optional
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=65535
// +kubebuilder:validation:MaxLength=100
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:Pattern="^[a-z]+$"
// +kubebuilder:validation:Enum=value1;value2;value3
// +kubebuilder:default="value"
```

### API design rules

- Use `metav1.Condition` for status (not custom string fields)
- Use `metav1.Time` for timestamps (not `string`)
- Follow K8s API conventions: standard field names (`spec`, `status`, `metadata`)
- Store external resource identifiers (OPNsense UUIDs) in `.status`, not `.spec`
- Use `ObservedGeneration` in status to signal whether the controller has processed the latest spec
- Set `Ready=False` with a descriptive message on any error; never leave a stale `Ready=True`

## Controller RBAC markers (`internal/controller/*_controller.go`)

```go
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/finalizers,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
```

## Controller implementation patterns

```go
// Re-fetch before updates to avoid resource version conflicts
if err := r.Get(ctx, req.NamespacedName, obj); err != nil { ... }

// Return values
return ctrl.Result{}, nil                                    // success, done
return ctrl.Result{Requeue: true}, nil                       // retry immediately
return ctrl.Result{RequeueAfter: 30 * time.Second}, nil      // retry after delay

// Structured logging
log := log.FromContext(ctx)
log.Info("Created Deployment", "name", deploy.Name)
log.Error(err, "Failed to create Pod", "name", name)

// Owner references (enables automatic garbage collection)
ctrl.SetControllerReference(owner, child, r.Scheme)
```

### Watch secondary resources

Use `.Owns()` or `.Watches()` in `SetupWithManager`, not just `RequeueAfter`:

```go
return ctrl.NewControllerManagedBy(mgr).
    For(&myv1.MyKind{}).
    Owns(&appsv1.Deployment{}).
    Complete(r)
```

## Webhooks

```bash
# Validation + defaulting
kubebuilder create webhook --group <group> --version <version> --kind <Kind> \
  --defaulting --programmatic-validation

# Conversion webhook (multi-version APIs)
kubebuilder create webhook --group <group> --version v1 --kind <Kind> \
  --conversion --spoke v2
```

Hub-and-spoke pattern: v1 is the hub (oldest stable), v2+ are spokes that convert to/from hub. Example: `v1` is hub, `v2` is spoke.

## References

- **Kubebuilder Book**: https://book.kubebuilder.io
- **Markers Reference**: https://book.kubebuilder.io/reference/markers.html
- **controller-runtime FAQ**: https://github.com/kubernetes-sigs/controller-runtime/blob/main/FAQ.md
- **Good Practices**: https://book.kubebuilder.io/reference/good-practices.html
- **API Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- **Operator Pattern**: https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
- **controller-runtime**: https://github.com/kubernetes-sigs/controller-runtime
- **controller-tools**: https://github.com/kubernetes-sigs/controller-tools
