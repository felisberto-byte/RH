resource "google_service_account" "portal" {
  account_id   = "${var.name}-run"
  display_name = "Portal do Colaborador (Cloud Run)"
}

resource "google_service_account" "scheduler" {
  account_id   = "${var.name}-scheduler"
  display_name = "Portal do Colaborador (Cloud Scheduler)"
}

# Bucket: criar e ler objetos — sem permissão de apagar/sobrescrever.
resource "google_storage_bucket_iam_member" "portal_create" {
  bucket = google_storage_bucket.documents.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.portal.email}"
}

resource "google_storage_bucket_iam_member" "portal_read" {
  bucket = google_storage_bucket.documents.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.portal.email}"
}

resource "google_secret_manager_secret_iam_member" "generated" {
  for_each  = google_secret_manager_secret.generated
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.portal.email}"
}

resource "google_secret_manager_secret_iam_member" "external" {
  for_each  = google_secret_manager_secret.external
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.portal.email}"
}

resource "google_project_iam_member" "portal_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.portal.email}"
}

resource "google_project_iam_member" "portal_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.portal.email}"
}
