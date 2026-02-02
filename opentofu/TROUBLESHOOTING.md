# Troubleshooting

## Common Issues

### SSH Connection Failed
- **Cause**: Cloud-init might not have finished or network is misconfigured.
- **Fix**: Check Proxmox console for the VM. Verify IP address. Ensure SSH key is correct.

### K3s Startup Failed
- **Cause**: Low memory.
- **Fix**: Check system logs `journalctl -u k3s`. Verify `eviction-hard` settings in `modules/k3s/main.tf`. Increase VM RAM.

### Helm Timeout
- **Cause**: API server slow or network issues.
- **Fix**: Run `tofu apply` again. OpenTofu will retry.

### Longhorn Volumes Not Scheduling
- **Cause**: Not enough nodes or disk space.
- **Fix**: Check `kubectl -n longhorn-system get nodes`. Ensure `defaultClassReplicaCount` is not higher than node count.

## Debugging

Use `scripts/verify-cluster.sh` to get an overview.
Check logs of specific components:
```bash
kubectl logs -n traefik -l app.kubernetes.io/name=traefik
kubectl logs -n monitoring -l app.kubernetes.io/name=grafana
```
