# ── Credentials ──────────────────────────────────────────────────────────────
variable "hcloud_token" {
  description = "Hetzner Cloud API token with read+write on the target project."
  type        = string
  sensitive   = true
}

# ── Naming & placement ───────────────────────────────────────────────────────
variable "project_name" {
  description = "Prefix applied to every created resource."
  type        = string
  default     = "agenticir"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 2-31 chars."
  }
}

variable "environment" {
  description = "Environment label (prod, staging, ...). Becomes part of resource names."
  type        = string
  default     = "prod"
}

variable "location" {
  description = "Hetzner location. nbg1/fsn1/hel1 are EU; ash/hil are US; sin is APAC."
  type        = string
  default     = "nbg1"

  validation {
    condition     = contains(["nbg1", "fsn1", "hel1", "ash", "hil", "sin"], var.location)
    error_message = "location must be one of: nbg1, fsn1, hel1, ash, hil, sin."
  }
}

# ── Compute ──────────────────────────────────────────────────────────────────
variable "server_type" {
  description = <<-EOT
    Hetzner server type. The stack (LangGraph API + Postgres + Redis + n8n +
    Coolify itself) wants 8 vCPU / 16-32 GB to run comfortably.

      cax31  8 vCPU ARM64, 16 GB  — best price/performance, recommended
      cax41 16 vCPU ARM64, 32 GB  — headroom for local inference
      cpx41  8 vCPU x86,   16 GB  — if you need x86-only images
      cpx51 16 vCPU x86,   32 GB
  EOT
  type        = string
  default     = "cax31"
}

variable "server_image" {
  description = "Base OS image."
  type        = string
  default     = "ubuntu-24.04"
}

variable "enable_backups" {
  description = "Hetzner automated backups (+20% of server cost). Independent of volume snapshots."
  type        = bool
  default     = true
}

# ── Storage ──────────────────────────────────────────────────────────────────
variable "data_volume_size" {
  description = <<-EOT
    Size in GB of the persistent data volume mounted at /data, which holds all
    Coolify state, Postgres data and n8n workflows. Set to 0 to keep everything
    on the server's own disk (not recommended — you lose the ability to detach
    and reattach data when resizing the server). Minimum 10 when enabled.
  EOT
  type        = number
  default     = 50

  validation {
    condition     = var.data_volume_size == 0 || var.data_volume_size >= 10
    error_message = "data_volume_size must be 0 (disabled) or at least 10 GB."
  }
}

# ── Access ───────────────────────────────────────────────────────────────────
variable "ssh_public_key" {
  description = "SSH public key content granted root access to the server."
  type        = string

  validation {
    condition     = can(regex("^(ssh-(rsa|ed25519)|ecdsa-sha2-)", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be an OpenSSH public key (ssh-ed25519, ssh-rsa or ecdsa-sha2-*)."
  }
}

variable "admin_ips" {
  description = <<-EOT
    CIDRs allowed to reach SSH and the Coolify dashboard. Defaulting this to
    0.0.0.0/0 would put your whole control plane on the public internet, so it
    is required — set it to your office/VPN egress, e.g. ["203.0.113.4/32"].
    Use ["0.0.0.0/0", "::/0"] only if you accept that risk knowingly.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.admin_ips) > 0
    error_message = "Provide at least one CIDR in admin_ips."
  }
}

# ── DNS / URLs ───────────────────────────────────────────────────────────────
variable "base_domain" {
  description = <<-EOT
    Apex domain for the deployment, e.g. "ir.example.com". Services are exposed
    as app.<base_domain>, n8n.<base_domain>, coolify.<base_domain>.

    Leave empty to fall back to sslip.io wildcard DNS (<ip>.sslip.io), which
    resolves without any DNS configuration and still gets real Let's Encrypt
    certificates. Good for a first bring-up; move to a real domain for production.
  EOT
  type        = string
  default     = ""
}

# ── Behaviour ────────────────────────────────────────────────────────────────
variable "install_coolify" {
  description = "Run the Coolify installer via cloud-init. Disable to get a bare hardened Docker host."
  type        = bool
  default     = true
}

variable "timezone" {
  description = "System timezone."
  type        = string
  default     = "UTC"
}

variable "swap_size_gb" {
  description = "Swap file size in GB. Cheap insurance against OOM during LLM bursts."
  type        = number
  default     = 4
}

variable "labels" {
  description = "Extra labels applied to all resources."
  type        = map(string)
  default     = {}
}
