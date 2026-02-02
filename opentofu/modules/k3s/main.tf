resource "local_file" "ssh_key" {
  content         = var.ssh_private_key
  filename        = "${path.module}/.ssh_key"
  file_permission = "0600"
}

resource "null_resource" "k3s_control_plane" {
  connection {
    type        = "ssh"
    user        = var.ssh_user
    private_key = var.ssh_private_key
    host        = var.control_plane_ip
  }

  provisioner "remote-exec" {
    inline = [
      "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --disable traefik --write-kubeconfig-mode 644 --kubelet-arg=eviction-hard=memory.available<500Mi --kubelet-arg=eviction-soft=memory.available<1Gi' sh -",
      "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
      "until sudo kubectl get nodes; do sleep 5; done"
    ]
  }
}

resource "null_resource" "k3s_token" {
  depends_on = [null_resource.k3s_control_plane]

  provisioner "local-exec" {
    command = "ssh -o StrictHostKeyChecking=no -i ${local_file.ssh_key.filename} ${var.ssh_user}@${var.control_plane_ip} sudo cat /var/lib/rancher/k3s/server/node-token > /tmp/k3s_token"
  }
}

data "local_file" "k3s_token" {
  depends_on = [null_resource.k3s_token]
  filename   = "/tmp/k3s_token"
}

resource "null_resource" "k3s_workers" {
  for_each = var.worker_ips
  depends_on = [data.local_file.k3s_token]

  connection {
    type        = "ssh"
    user        = var.ssh_user
    private_key = var.ssh_private_key
    host        = each.value
  }

  provisioner "remote-exec" {
    inline = [
      "curl -sfL https://get.k3s.io | K3S_URL=https://${var.control_plane_ip}:6443 K3S_TOKEN=${trimspace(data.local_file.k3s_token.content)} sh -",
    ]
  }
}

resource "null_resource" "get_kubeconfig" {
  depends_on = [null_resource.k3s_control_plane]

  provisioner "local-exec" {
    command = "scp -o StrictHostKeyChecking=no -i ${local_file.ssh_key.filename} ${var.ssh_user}@${var.control_plane_ip}:/etc/rancher/k3s/k3s.yaml /tmp/k3s.yaml && sed -i 's/127.0.0.1/${var.control_plane_ip}/g' /tmp/k3s.yaml"
  }
}

data "local_file" "kubeconfig" {
  depends_on = [null_resource.get_kubeconfig]
  filename   = "/tmp/k3s.yaml"
}
