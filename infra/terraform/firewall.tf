# Cloud-level firewall. This is enforced by Hetzner before traffic reaches the
# host, and is independent of the UFW rules cloud-init sets up — belt and braces,
# so a misconfigured host firewall does not expose the control plane.

resource "hcloud_firewall" "main" {
  name   = "${local.name}-fw"
  labels = local.common_labels

  # ── Public web traffic: terminates at Coolify's proxy ──
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "HTTP (redirects to HTTPS, serves ACME challenges)"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "HTTPS — Slack events, n8n webhooks, dashboard, API"
  }

  # ── Administrative access: restricted to admin_ips ──
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.admin_ips
    description = "SSH (key-only)"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "8000"
    source_ips  = var.admin_ips
    description = "Coolify dashboard before a domain is attached"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "6001"
    source_ips  = var.admin_ips
    description = "Coolify realtime websocket"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "6002"
    source_ips  = var.admin_ips
    description = "Coolify terminal websocket"
  }

  # ── ICMP for reachability debugging ──
  rule {
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "ping"
  }

  # Note: Hetzner firewalls allow all egress when no "out" rules are declared.
  # Agents need outbound HTTPS to LLM providers and threat-intel APIs, so we
  # deliberately leave egress open rather than enumerating provider IP ranges.
}
