locals {
  public_ip = hcloud_floating_ip.main.ip_address

  # With no domain configured, fall back to sslip.io wildcard DNS: it resolves
  # <anything>.<ip>.sslip.io to <ip> with no DNS setup, and still satisfies
  # Let's Encrypt HTTP-01 challenges.
  effective_domain = var.base_domain != "" ? var.base_domain : "${replace(local.public_ip, ".", "-")}.sslip.io"

  app_fqdn     = "app.${local.effective_domain}"
  n8n_fqdn     = "n8n.${local.effective_domain}"
  coolify_fqdn = "coolify.${local.effective_domain}"
}

output "server_id" {
  description = "Hetzner server ID."
  value       = hcloud_server.main.id
}

output "server_ipv4" {
  description = "The server's own public IPv4."
  value       = hcloud_server.main.ipv4_address
}

output "public_ip" {
  description = "Floating IP — point DNS here, not at the server address."
  value       = local.public_ip
}

output "server_ipv6" {
  description = "Public IPv6 address."
  value       = hcloud_server.main.ipv6_address
}

output "ssh_command" {
  description = "SSH into the host."
  value       = "ssh root@${local.public_ip}"
}

output "coolify_setup_url" {
  description = "Open this first to create the Coolify admin account."
  value       = "http://${local.public_ip}:8000"
}

output "app_url" {
  description = "AgenticIR dashboard once deployed."
  value       = "https://${local.app_fqdn}"
}

output "n8n_url" {
  description = "n8n editor once deployed."
  value       = "https://${local.n8n_fqdn}"
}

output "app_fqdn" {
  description = "Hostname for the API/dashboard — feed this to the Coolify bootstrap."
  value       = local.app_fqdn
}

output "n8n_fqdn" {
  description = "Hostname for n8n — feed this to the Coolify bootstrap."
  value       = local.n8n_fqdn
}

output "coolify_fqdn" {
  description = "Hostname to attach to the Coolify dashboard itself."
  value       = local.coolify_fqdn
}

output "using_sslip_fallback" {
  description = "True when no base_domain was set and sslip.io DNS is in use."
  value       = var.base_domain == ""
}

output "dns_records_required" {
  description = "DNS records to create. Empty when using the sslip.io fallback."
  value = var.base_domain == "" ? [] : [
    "A  ${local.app_fqdn}      -> ${local.public_ip}",
    "A  ${local.n8n_fqdn}      -> ${local.public_ip}",
    "A  ${local.coolify_fqdn}  -> ${local.public_ip}",
  ]
}

output "bootstrap_env" {
  description = <<-EOT
    Shell snippet for the Coolify bootstrap step. Usage:

      eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"
      export COOLIFY_API_TOKEN=...   # created in the Coolify UI
      make coolify-deploy
  EOT
  value = join("\n", [
    "export COOLIFY_URL=http://${local.public_ip}:8000",
    "export SERVER_IP=${local.public_ip}",
    "export APP_FQDN=${local.app_fqdn}",
    "export N8N_FQDN=${local.n8n_fqdn}",
  ])
}

output "next_steps" {
  description = "What to do after apply."
  value       = <<-EOT

    ┌─ AgenticIR infrastructure ready ───────────────────────────────────────┐

    1. Wait for cloud-init to finish installing Coolify (~5-10 min):
         make coolify-wait
       or watch it directly:
         ssh root@${local.public_ip} tail -f /var/log/agenticir-bootstrap.log

    2. Create the Coolify admin account (first visitor claims it — do this now):
         ${"http://${local.public_ip}:8000"}

    3. In Coolify: Keys & Tokens → API tokens → create one with read/write.

    4. Deploy the application stack:
         eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"
         export COOLIFY_API_TOKEN=<the token from step 3>
         make coolify-deploy

    5. Surfaces once deployed:
         Dashboard  https://${local.app_fqdn}/ui
         API docs   https://${local.app_fqdn}/docs
         n8n        https://${local.n8n_fqdn}
    %{~if var.base_domain != ""}

    DNS: point these at ${local.public_ip} before step 4, or TLS issuance fails.
         ${local.app_fqdn}
         ${local.n8n_fqdn}
    %{~endif}
    %{~if var.base_domain == ""}

    No base_domain set — using sslip.io wildcard DNS, which needs no setup.
    Set base_domain in terraform.tfvars for a production deployment.
    %{~endif}

    └────────────────────────────────────────────────────────────────────────┘
  EOT
}
