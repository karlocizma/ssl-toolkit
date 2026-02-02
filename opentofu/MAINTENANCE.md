# Maintenance Guide

## Scaling

To add nodes:
1. Add new entry to `worker_nodes` variable.
2. Run `tofu apply`.

To remove nodes:
1. Drain the node via `kubectl drain <node-name>`.
2. Remove entry from `worker_nodes` variable.
3. Run `tofu apply`.

## Upgrades

### K3s Upgrade
K3s supports automated upgrades using the System Upgrade Controller, or you can manually upgrade the binary on nodes and restart the service.

### Helm Chart Upgrades
Update the `version` attribute in the `helm_release` resources in the modules and run `tofu apply`.

## Backups

### Longhorn
Configure S3 backup target in Longhorn UI to enable volume backups.

### Etcd (Control Plane)
K3s automatically takes snapshots. They are located at `/var/lib/rancher/k3s/server/db/snapshots/`.

## Cleanup

To destroy the cluster:
```bash
./scripts/cleanup.sh
```
