# PDFs (originais, emitidos, com aceite, comprovantes) e âncoras da auditoria.
# - retention_policy: nenhum objeto pode ser apagado/sobrescrito antes do prazo
#   (WORM). lock_retention_policy=true torna a regra IRREVERSÍVEL (Bucket Lock).
# - A conta do portal só cria e lê objetos (sem delete).
resource "google_storage_bucket" "documents" {
  name                        = "${var.project_id}-${var.name}-documentos"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = var.documents_retention_days * 86400
    is_locked        = var.lock_retention_policy
  }

  soft_delete_policy {
    retention_duration_seconds = 30 * 86400
  }

  depends_on = [google_project_service.apis]
}
