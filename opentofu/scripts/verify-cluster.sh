#!/bin/bash
set -e

# Check for tofu or terraform
if command -v tofu &> /dev/null; then
    TF_CMD="tofu"
elif command -v terraform &> /dev/null; then
    TF_CMD="terraform"
else
    echo "OpenTofu or Terraform not found."
    exit 1
fi

cd "$(dirname "$0")/.."

echo "Extracting kubeconfig..."
$TF_CMD output -raw kubeconfig > /tmp/tofu_kubeconfig.yaml

export KUBECONFIG=/tmp/tofu_kubeconfig.yaml

echo "Checking Nodes..."
kubectl get nodes -o wide

echo "Checking Pods..."
kubectl get pods -A

echo "Checking for any non-running pods..."
kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded

echo "Checking Longhorn..."
kubectl -n longhorn-system get pods

echo "Checking Traefik..."
kubectl -n traefik get pods

echo "Checking Monitoring..."
kubectl -n monitoring get pods
