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

echo "Destroying infrastructure..."
$TF_CMD destroy
