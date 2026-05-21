# Deployment & Distribution

## Local development

```bash
make run  # Run locally using current kubeconfig context
```

## Deploy to cluster

```bash
# 1. Regenerate manifests
make manifests generate

# 2. Build and push image
export IMG=<registry>/<project>:<tag>
make docker-build docker-push IMG=$IMG
# Or load directly into Kind:
kind load docker-image $IMG --name <cluster>

# 3. Deploy
make deploy IMG=$IMG

# 4. Apply sample CRs
kubectl apply -k config/samples/

# 5. Debug
kubectl logs -n <project>-system deployment/<project>-controller-manager -c manager -f
```

## Distribution: YAML bundle (Kustomize)

```bash
make build-installer IMG=<registry>/<project>:<tag>
# Generates dist/install.yaml — commit this file to the repository
```

Users install with a single command:

```bash
kubectl apply -f https://raw.githubusercontent.com/<org>/<repo>/<tag>/dist/install.yaml
```

## Distribution: Helm chart

```bash
# Generate chart
kubebuilder edit --plugins=helm/v2-alpha                      # → dist/chart/
kubebuilder edit --plugins=helm/v2-alpha --output-dir=charts  # → charts/chart/
```

Development:

```bash
make helm-deploy IMG=<registry>/<project>:<tag>
make helm-deploy IMG=$IMG HELM_EXTRA_ARGS="--set ..."
make helm-status
make helm-uninstall
make helm-history
make helm-rollback
```

End users:

```bash
helm install my-release ./<output-dir>/chart/ --namespace <ns> --create-namespace
```

**If you add webhooks or change manifests after chart generation:**

1. Backup `<output-dir>/chart/values.yaml` and `<output-dir>/chart/manager/manager.yaml`
2. Re-run: `kubebuilder edit --plugins=helm/v2-alpha --force` (use same `--output-dir`)
3. Restore your customizations from the backup

## Publish container image

```bash
export IMG=<registry>/<project>:<version>
make docker-build docker-push IMG=$IMG
```
