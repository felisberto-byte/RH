# Cloud VPN Classic baseada em rotas (rotas estáticas): funciona com firewalls sem
# BGP. Se o equipamento da empresa suportar BGP, prefira HA VPN (99,99% de SLA,
# dois túneis + Cloud Router) — ver docs/implantacao-gcp.md.
locals {
  create_vpn = var.vpn_peer_ip != ""
}

resource "google_compute_vpn_gateway" "classic" {
  count   = local.create_vpn ? 1 : 0
  name    = "${var.name}-vpn-gw"
  network = google_compute_network.vpc.id
  region  = var.region
}

resource "google_compute_address" "vpn" {
  count  = local.create_vpn ? 1 : 0
  name   = "${var.name}-vpn-ip"
  region = var.region
}

resource "google_compute_forwarding_rule" "esp" {
  count       = local.create_vpn ? 1 : 0
  name        = "${var.name}-vpn-esp"
  region      = var.region
  ip_protocol = "ESP"
  ip_address  = google_compute_address.vpn[0].address
  target      = google_compute_vpn_gateway.classic[0].id
}

resource "google_compute_forwarding_rule" "udp500" {
  count       = local.create_vpn ? 1 : 0
  name        = "${var.name}-vpn-udp500"
  region      = var.region
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.vpn[0].address
  target      = google_compute_vpn_gateway.classic[0].id
}

resource "google_compute_forwarding_rule" "udp4500" {
  count       = local.create_vpn ? 1 : 0
  name        = "${var.name}-vpn-udp4500"
  region      = var.region
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.vpn[0].address
  target      = google_compute_vpn_gateway.classic[0].id
}

resource "google_compute_vpn_tunnel" "onprem" {
  count                   = local.create_vpn ? 1 : 0
  name                    = "${var.name}-vpn-tunnel"
  region                  = var.region
  peer_ip                 = var.vpn_peer_ip
  shared_secret           = var.vpn_shared_secret
  ike_version             = 2
  target_vpn_gateway      = google_compute_vpn_gateway.classic[0].id
  local_traffic_selector  = ["0.0.0.0/0"]
  remote_traffic_selector = ["0.0.0.0/0"]
  depends_on = [
    google_compute_forwarding_rule.esp,
    google_compute_forwarding_rule.udp500,
    google_compute_forwarding_rule.udp4500,
  ]
}

resource "google_compute_route" "onprem" {
  for_each            = local.create_vpn ? toset(var.onprem_cidrs) : toset([])
  name                = "${var.name}-to-onprem-${replace(replace(each.value, ".", "-"), "/", "-")}"
  network             = google_compute_network.vpc.id
  dest_range          = each.value
  priority            = 1000
  next_hop_vpn_tunnel = google_compute_vpn_tunnel.onprem[0].id
}
