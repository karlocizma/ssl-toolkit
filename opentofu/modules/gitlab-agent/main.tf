terraform {
  required_providers {
    helm = {
      source = "hashicorp/helm"
    }
  }
}

resource "helm_release" "gitlab_agent" {
  name       = "gitlab-agent"
  repository = "https://charts.gitlab.io"
  chart      = "gitlab-agent"
  namespace  = "gitlab-agent"
  create_namespace = true

  set {
    name  = "config.token"
    value = var.agent_token
  }

  set {
    name  = "config.kasAddress"
    value = var.kas_address
  }
}
