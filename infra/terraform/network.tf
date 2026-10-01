# VPC dedicada; o Cloud Run sai por Direct VPC egress (sem conector) apenas para
# faixas privadas (Cloud SQL privado e DCs via VPN).
resource "google_compute_network" "vpc" {
  name                    = "${var.name}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "run" {
  name                     = "${var.name}-run-egress"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

# Somente LDAPS (636) para os DCs a partir das instâncias marcadas ldap-client.
resource "google_compute_firewall" "ldaps_to_dc" {
  name               = "${var.name}-allow-ldaps-dc"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 900
  target_tags        = ["ldap-client"]
  destination_ranges = [for ip in var.dc_ips : "${ip}/32"]
  allow {
    protocol = "tcp"
    ports    = ["636"]
  }
}

resource "google_compute_firewall" "deny_other_onprem" {
  name               = "${var.name}-deny-onprem"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  target_tags        = ["ldap-client"]
  destination_ranges = var.onprem_cidrs
  deny {
    protocol = "all"
  }
}

# Acesso privado ao Cloud SQL (peering do Service Networking).
resource "google_compute_global_address" "sql_peering" {
  name          = "${var.name}-sql-peering"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "sql" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_peering.name]
}

# Zona DNS privada para resolver o FQDN dos DCs (validação TLS do LDAPS).
resource "google_dns_managed_zone" "ad" {
  count       = var.ad_dns_domain == "" ? 0 : 1
  name        = "${var.name}-ad"
  dns_name    = var.ad_dns_domain
  visibility  = "private"
  description = "Registros dos controladores de domínio (somente leitura no GCP)"
  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_dns_record_set" "dc" {
  for_each     = var.ad_dns_domain == "" ? {} : var.dc_dns_records
  managed_zone = google_dns_managed_zone.ad[0].name
  name         = "${each.key}.${var.ad_dns_domain}"
  type         = "A"
  ttl          = 300
  rrdatas      = [each.value]
}
