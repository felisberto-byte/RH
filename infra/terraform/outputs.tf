output "load_balancer_ip" {
  description = "Crie o registro DNS A de var.domain apontando para este IP."
  value       = google_compute_global_address.lb.address
}

output "vpn_gateway_ip" {
  description = "IP público do GCP para configurar o túnel IPsec no firewall da empresa."
  value       = try(google_compute_address.vpn[0].address, null)
}

output "run_egress_subnet" {
  description = "Libere no firewall da empresa: esta faixa -> DCs, TCP 636."
  value       = google_compute_subnetwork.run.ip_cidr_range
}

output "documents_bucket" {
  value = google_storage_bucket.documents.name
}

output "cloud_sql_private_ip" {
  value = google_sql_database_instance.portal.private_ip_address
}

output "secrets_to_load" {
  description = "Segredos que o operador deve carregar (gcloud secrets versions add)."
  value       = [for s in google_secret_manager_secret.external : s.secret_id]
}

output "artifact_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.portal.repository_id}"
}
