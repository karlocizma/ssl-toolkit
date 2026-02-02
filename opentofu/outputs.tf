output "kubeconfig" {
  value     = module.k3s.kubeconfig
  sensitive = true
}

output "control_plane_ip" {
  value = module.proxmox_vm.control_plane_ip
}

output "worker_ips" {
  value = module.proxmox_vm.worker_ips
}
