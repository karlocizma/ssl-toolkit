terraform {
  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
    }
  }
}

resource "proxmox_vm_qemu" "control_plane" {
  name        = "k3s-control"
  target_node = var.proxmox_node
  clone       = var.template_name
  agent       = 1
  os_type     = "cloud-init"
  cores       = 2
  sockets     = 1
  cpu         = "host"
  memory      = 4096
  scsihw      = "virtio-scsi-pci"
  bootdisk    = "scsi0"

  disk {
    slot = 0
    size = "20G"
    type = "scsi"
    storage = "local-lvm"
    iothread = 1
  }

  network {
    model  = "virtio"
    bridge = "vmbr0"
  }

  lifecycle {
    ignore_changes = [
      network,
    ]
  }

  ipconfig0 = "ip=${var.control_plane_ip}/24,gw=${var.gateway}"
  nameserver = join(" ", var.dns_servers)
  
  sshkeys = <<EOF
  ${var.ssh_public_key}
  EOF
}

resource "proxmox_vm_qemu" "workers" {
  for_each    = var.worker_nodes
  name        = "k3s-${each.key}"
  target_node = var.proxmox_node
  clone       = var.template_name
  agent       = 1
  os_type     = "cloud-init"
  cores       = 2
  sockets     = 1
  cpu         = "host"
  memory      = 3072
  scsihw      = "virtio-scsi-pci"
  bootdisk    = "scsi0"

  disk {
    slot = 0
    size = "20G"
    type = "scsi"
    storage = "local-lvm"
    iothread = 1
  }

  network {
    model  = "virtio"
    bridge = "vmbr0"
  }

  lifecycle {
    ignore_changes = [
      network,
    ]
  }

  ipconfig0 = "ip=${each.value.ip}/24,gw=${var.gateway}"
  nameserver = join(" ", var.dns_servers)
  
  sshkeys = <<EOF
  ${var.ssh_public_key}
  EOF
}
