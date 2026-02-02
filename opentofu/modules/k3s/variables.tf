variable "control_plane_ip" { type = string }
variable "worker_ips" { type = map(string) }
variable "ssh_user" { type = string }
variable "ssh_private_key" { type = string }
