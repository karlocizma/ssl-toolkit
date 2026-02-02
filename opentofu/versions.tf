terraform {
  required_version = ">= 1.6.0"

  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
      version = "3.0.1-rc1"
    }
    helm = {
        source = "hashicorp/helm"
        version = "~> 2.12.0"
    }
    kubernetes = {
        source = "hashicorp/kubernetes"
        version = "~> 2.25.0"
    }
  }
}
