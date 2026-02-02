# Configuration Guide

## Customizing Cluster Size

To change the number of worker nodes, update `variables.tf` or `terraform.tfvars`:

```hcl
worker_nodes = {
  worker1 = { ip = "10.0.0.101" }
  worker2 = { ip = "10.0.0.102" }
  worker3 = { ip = "10.0.0.103" }
}
```

## Changing IPs and Network

Adjust the following variables:
- `control_plane_ip`
- `gateway`
- `dns_servers`

## Resource Limits

To change CPU/RAM for VMs, edit `modules/proxmox-vm/main.tf`.

To adjust K3s memory reservation (for low RAM environments), edit `modules/k3s/main.tf` and modify the `INSTALL_K3S_EXEC` args:
```bash
--kubelet-arg=eviction-hard=memory.available<500Mi
```

## Storage

Longhorn default replica count is set to 2 in `modules/storage/main.tf`. You can increase this to 3 if you add more workers.
