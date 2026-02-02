provider "proxmox" {
  pm_api_url          = var.proxmox_api_url
  pm_api_token_id     = var.proxmox_api_token_id
  pm_api_token_secret = var.proxmox_api_token_secret
  pm_tls_insecure     = true # Usually needed for self-signed Proxmox certs
}

module "proxmox_vm" {
  source = "./modules/proxmox-vm"

  proxmox_node   = var.proxmox_node
  template_name  = var.template_name
  ssh_public_key = var.ssh_public_key
  
  control_plane_ip = var.control_plane_ip
  worker_nodes     = var.worker_nodes
  gateway          = var.gateway
  dns_servers      = var.dns_servers
}

module "k3s" {
  source = "./modules/k3s"
  
  control_plane_ip = module.proxmox_vm.control_plane_ip
  worker_ips       = module.proxmox_vm.worker_ips
  ssh_user         = "debian" # Assuming default cloud-init user for Debian
  ssh_private_key  = file("~/.ssh/id_rsa") # Expected to be available
  
  depends_on = [module.proxmox_vm]
}

provider "kubernetes" {
  host = "https://${module.proxmox_vm.control_plane_ip}:6443"
  client_certificate     = module.k3s.client_certificate
  client_key             = module.k3s.client_key
  cluster_ca_certificate = module.k3s.cluster_ca_certificate
}

provider "helm" {
  kubernetes {
    host = "https://${module.proxmox_vm.control_plane_ip}:6443"
    client_certificate     = module.k3s.client_certificate
    client_key             = module.k3s.client_key
    cluster_ca_certificate = module.k3s.cluster_ca_certificate
  }
}

module "storage" {
  source = "./modules/storage"
  depends_on = [module.k3s]
}

module "monitoring" {
  source = "./modules/monitoring"
  depends_on = [module.storage] # Needs storage for persistence
}

module "ingress" {
  source = "./modules/ingress"
  depends_on = [module.k3s]
}

module "cert_manager" {
  source = "./modules/cert-manager"
  
  cloudflare_api_token = var.cloudflare_api_token
  cloudflare_email     = var.cloudflare_email
  
  depends_on = [module.ingress]
}

module "gitlab_agent" {
  source = "./modules/gitlab-agent"
  
  agent_token = var.gitlab_agent_token
  kas_address = var.gitlab_kas_address
  
  depends_on = [module.k3s]
}
