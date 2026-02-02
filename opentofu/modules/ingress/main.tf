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

resource "helm_release" "traefik" {
  name       = "traefik"
  repository = "https://traefik.github.io/charts"
  chart      = "traefik"
  namespace  = "traefik"
  create_namespace = true

  set {
    name  = "ingressClass.enabled"
    value = "true"
  }
  
  set {
    name  = "ingressClass.isDefaultClass"
    value = "true"
  }
  
  set {
    name = "dashboard.enabled"
    value = "true"
  }
  
  set {
    name = "dashboard.domain"
    value = "traefik.localhost"
  }
}

# Example IngressRoute for Traefik Dashboard (if needed explicitly, but dashboard.enabled usually handles it or provides a service)
# Usually we want to expose it securely.
