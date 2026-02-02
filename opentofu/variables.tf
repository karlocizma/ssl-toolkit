variable "proxmox_api_url" {
  description = "The URL of the Proxmox API (e.g., https://proxmox.example.com:8006/api2/json)"
  type        = string
}

variable "proxmox_api_token_id" {
  description = "The Token ID for Proxmox API authentication"
  type        = string
  sensitive   = true
}

variable "proxmox_api_token_secret" {
  description = "The Token Secret for Proxmox API authentication"
  type        = string
  sensitive   = true
}

variable "proxmox_node" {
  description = "The Proxmox node to deploy VMs on"
  type        = string
  default     = "pve"
}

variable "template_name" {
  description = "The name of the Cloud-Init template to clone"
  type        = string
  default     = "debian-12-cloudinit-template"
}

variable "ssh_public_key" {
  description = "SSH public key to inject into VMs"
  type        = string
}

variable "control_plane_ip" {
  description = "Static IP for the control plane node"
  type        = string
  default     = "10.0.0.100"
}

variable "worker_nodes" {
  description = "Map of worker nodes and their IPs"
  type = map(object({
    ip = string
  }))
  default = {
    worker1 = { ip = "10.0.0.101" }
    worker2 = { ip = "10.0.0.102" }
  }
}

variable "gateway" {
  description = "Network gateway"
  type        = string
  default     = "10.0.0.1"
}

variable "dns_servers" {
  description = "List of DNS servers"
  type        = list(string)
  default     = ["10.0.0.10", "10.0.0.11"]
}

variable "cloudflare_api_token" {
  description = "Cloudflare API Token for DNS challenges"
  type        = string
  sensitive   = true
}

variable "cloudflare_email" {
  description = "Cloudflare Email for ACME registration"
  type        = string
}

variable "gitlab_agent_token" {
  description = "Token for GitLab Agent"
  type        = string
  sensitive   = true
}

variable "gitlab_kas_address" {
    description = "GitLab KAS address"
    type = string
    default = "wss://kas.gitlab.com"
}
