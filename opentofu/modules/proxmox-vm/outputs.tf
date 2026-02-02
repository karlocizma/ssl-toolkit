output "control_plane_ip" {
  value = var.control_plane_ip
}

output "worker_ips" {
  value = { for k, v in var.worker_nodes : k => v.ip }
}
