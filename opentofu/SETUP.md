# Setup Guide

## Prerequisites

1. **Proxmox VE**: A running Proxmox VE server (version 7.x or 8.x).
2. **OpenTofu** (or Terraform): Installed on your local machine.
3. **Cloud-Init Template**: A Debian 12 cloud-init ready template on Proxmox.
4. **SSH Key**: An SSH key pair for accessing the VMs.

## Proxmox API Token

1. Log in to your Proxmox web interface.
2. Go to **Datacenter** -> **Permissions** -> **API Tokens**.
3. Click **Add**.
4. Select user (e.g., `root@pam`), enter a Token ID (e.g., `terraform`), and uncheck "Privilege Separation" (unless you configured permissions carefully).
5. Copy the **Token ID** and **Secret**. You will need these.

## OpenTofu Initialization

1. Navigate to the `opentofu` directory:
   ```bash
   cd opentofu
   ```

2. Create a `terraform.tfvars` file based on your environment:
   ```hcl
   proxmox_api_url          = "https://192.168.1.100:8006/api2/json"
   proxmox_api_token_id     = "root@pam!terraform"
   proxmox_api_token_secret = "your-secret-uuid"
   proxmox_node             = "pve"
   ssh_public_key           = "ssh-rsa AAA..."
   
   cloudflare_api_token     = "your-cloudflare-token"
   cloudflare_email         = "email@example.com"
   
   gitlab_agent_token       = "your-agent-token"
   ```

3. Initialize OpenTofu:
   ```bash
   tofu init
   ```
