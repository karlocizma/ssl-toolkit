# Deployment Guide

## Step-by-Step Deployment

1. **Initialize**: Ensure you have run `tofu init` (see SETUP.md).

2. **Plan**: Preview the changes.
   ```bash
   tofu plan
   ```

3. **Apply**: Provision the infrastructure.
   ```bash
   tofu apply
   ```
   Type `yes` when prompted.

   This process will:
   - Clone 3 VMs from the template.
   - Configure IPs via Cloud-Init.
   - SSH into the control plane to install k3s.
   - Retrieve the join token.
   - SSH into worker nodes to join the cluster.
   - Install Longhorn, Monitoring Stack, Traefik, Cert-Manager, and GitLab Agent via Helm.

## Verification

Run the verification script to check the status of nodes and pods:

```bash
./scripts/verify-cluster.sh
```

## Accessing the Cluster

The `kubeconfig` is outputted by OpenTofu. You can extract it:

```bash
tofu output -raw kubeconfig > kubeconfig.yaml
export KUBECONFIG=$(pwd)/kubeconfig.yaml
kubectl get nodes
```

## Accessing Dashboards

- **Traefik Dashboard**: Accessible if ingress is configured, or use port-forward:
  ```bash
  kubectl -n traefik port-forward $(kubectl -n traefik get pods -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].metadata.name}') 9000:9000
  ```
- **Grafana**:
  ```bash
  kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 8080:80
  ```
  Login with `admin` / `admin` (or your configured password).
