variable "proxmox_node" { type = string }
variable "template_name" { type = string }
variable "ssh_public_key" { type = string }
variable "control_plane_ip" { type = string }
variable "worker_nodes" {
  type = map(object({
    ip = string
  }))
}
variable "gateway" { type = string }
variable "dns_servers" { type = list(string) }
