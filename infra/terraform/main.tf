locals {
  name = "${var.project_name}-${var.environment}"

  common_labels = merge(
    {
      project     = var.project_name
      environment = var.environment
      managed_by  = "terraform"
      component   = "agentic-ir"
    },
    var.labels,
  )

  volume_enabled = var.data_volume_size > 0
}

# ── SSH key ──────────────────────────────────────────────────────────────────
resource "hcloud_ssh_key" "admin" {
  name       = "${local.name}-admin"
  public_key = trimspace(var.ssh_public_key)
  labels     = local.common_labels
}

# ── Private network ──────────────────────────────────────────────────────────
# Not strictly required for a single node, but it means adding a second server
# (or a managed database) later does not require re-plumbing anything.
resource "hcloud_network" "main" {
  name     = "${local.name}-net"
  ip_range = "10.20.0.0/16"
  labels   = local.common_labels
}

resource "hcloud_network_subnet" "main" {
  network_id   = hcloud_network.main.id
  type         = "cloud"
  network_zone = contains(["ash", "hil"], var.location) ? "us-east" : (var.location == "sin" ? "ap-southeast" : "eu-central")
  ip_range     = "10.20.1.0/24"
}

# ── Persistent data volume ───────────────────────────────────────────────────
resource "hcloud_volume" "data" {
  count = local.volume_enabled ? 1 : 0

  name     = "${local.name}-data"
  size     = var.data_volume_size
  location = var.location
  format   = "ext4"
  labels   = local.common_labels

  lifecycle {
    # This volume holds every incident record, checkpoint and n8n workflow.
    prevent_destroy = true
  }
}

# ── Server ───────────────────────────────────────────────────────────────────
resource "hcloud_server" "main" {
  name        = local.name
  server_type = var.server_type
  image       = var.server_image
  location    = var.location
  ssh_keys    = [hcloud_ssh_key.admin.id]
  backups     = var.enable_backups
  labels      = local.common_labels

  firewall_ids = [hcloud_firewall.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.main.id
    ip         = "10.20.1.10"
  }

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    hostname = local.name
    timezone = var.timezone

    # Rendered separately so the bash never has to survive YAML block-scalar
    # indentation rules alongside Terraform template directives.
    bootstrap_script = templatefile("${path.module}/bootstrap.sh.tftpl", {
      swap_size_gb    = var.swap_size_gb
      install_coolify = var.install_coolify
      volume_enabled  = local.volume_enabled
      volume_device   = local.volume_enabled ? hcloud_volume.data[0].linux_device : ""
      admin_ips       = var.admin_ips
    })
  })

  depends_on = [hcloud_network_subnet.main]

  lifecycle {
    # user_data changes would otherwise force a rebuild, destroying the host.
    # Re-run cloud-init deliberately instead: `make tf-taint-server`.
    ignore_changes = [user_data, image]
  }
}

resource "hcloud_volume_attachment" "data" {
  count = local.volume_enabled ? 1 : 0

  volume_id = hcloud_volume.data[0].id
  server_id = hcloud_server.main.id
  automount = false # cloud-init handles mounting so /data exists before Coolify installs
}

# ── Static egress/ingress address ────────────────────────────────────────────
# A floating IP survives server rebuilds, so DNS records and Slack/n8n webhook
# URLs stay valid when the host is replaced.
resource "hcloud_floating_ip" "main" {
  type          = "ipv4"
  home_location = var.location
  description   = "${local.name} public entrypoint"
  labels        = local.common_labels
}

resource "hcloud_floating_ip_assignment" "main" {
  floating_ip_id = hcloud_floating_ip.main.id
  server_id      = hcloud_server.main.id
}
