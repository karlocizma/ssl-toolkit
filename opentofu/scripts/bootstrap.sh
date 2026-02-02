#!/bin/bash
set -e

# Check for tofu or terraform
if command -v tofu &> /dev/null; then
    TF_CMD="tofu"
elif command -v terraform &> /dev/null; then
    TF_CMD="terraform"
else
    echo "OpenTofu or Terraform not found. Please install one of them."
    exit 1
fi

echo "Initializing..."
cd "$(dirname "$0")/.."
$TF_CMD init

echo "Applying..."
$TF_CMD apply
