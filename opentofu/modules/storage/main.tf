terraform {
  required_providers {
    helm = {
      source = "hashicorp/helm"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
    }
  }
}

resource "helm_release" "longhorn" {
  name       = "longhorn"
  repository = "https://charts.longhorn.io"
  chart      = "longhorn"
  namespace  = "longhorn-system"
  create_namespace = true

  set {
    name  = "persistence.defaultClassReplicaCount"
    value = "2" # Since we have 2 workers, maybe 2 replicas is safer than 3.
  }
  
  set {
    name  = "persistence.defaultClass"
    value = "true"
  }
}
