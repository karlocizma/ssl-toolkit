# GitLab Integration

## Setting up GitLab Agent

1. **Create Agent Config**:
   In your GitLab project repo, create `.gitlab/agents/<agent-name>/config.yaml`.
   Example content:
   ```yaml
   gitops:
     manifest_projects:
       - id: "path/to/project"
   ```

2. **Register Agent**:
   - Go to **Operate** -> **Kubernetes clusters** in GitLab.
   - Select **Connect a cluster (agent)**.
   - Select the agent you defined in step 1.
   - You will get an **Agent Token**.

3. **Configure OpenTofu**:
   - Add the token to `terraform.tfvars`:
     ```hcl
     gitlab_agent_token = "your-token"
     ```
   - Run `tofu apply`.

## Auto DevOps

Once the agent is connected:
1. Go to **Settings** -> **CI/CD** -> **Auto DevOps**.
2. Enable "Default to Auto DevOps pipeline".
3. Ensure your `.gitlab-ci.yml` uses the agent context or standard `KUBECONFIG` if using certificate-based connection (deprecated). With Agent, you typically use the CI/CD tunnel.

To use CI/CD tunnel:
```yaml
deploy:
  image: dtzar/helm-kubectl
  script:
    - kubectl config use-context path/to/project:<agent-name>
    - kubectl get pods
```
