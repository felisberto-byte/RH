# Métricas a partir dos logs do portal (a aplicação registra cada evento de
# auditoria como "auditoria <ACAO> ...") e alertas de falha dos jobs.
resource "google_logging_metric" "integrity_failure" {
  name   = "${var.name}-integridade-falhou"
  filter = "resource.type=\"cloud_run_revision\" AND textPayload:\"auditoria INTEGRIDADE_FALHOU\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "login_failed" {
  name   = "${var.name}-login-falhou"
  filter = "resource.type=\"cloud_run_revision\" AND textPayload:\"auditoria LOGIN_FALHOU\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "job_failed" {
  name   = "${var.name}-job-falhou"
  filter = "resource.type=\"cloud_run_job\" AND severity>=ERROR"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Segunda cópia, imutável, dos eventos de auditoria do portal (além da cadeia de
# hashes no PostgreSQL): bucket de logs em São Paulo com retenção longa.
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.region
  bucket_id      = "${var.name}-auditoria"
  retention_days = var.audit_log_retention_days
  locked         = var.lock_audit_log_bucket
  description    = "Eventos de auditoria do Portal do Colaborador"
}

resource "google_logging_project_sink" "audit" {
  name                   = "${var.name}-auditoria"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.audit.id}"
  filter                 = "resource.type=(\"cloud_run_revision\" OR \"cloud_run_job\") AND textPayload:\"auditoria \""
  unique_writer_identity = true
}

# Logs de acesso a dados (quem leu PDFs do bucket, quem acessou segredos).
resource "google_project_iam_audit_config" "data_access" {
  for_each = toset(["storage.googleapis.com", "secretmanager.googleapis.com"])
  project  = var.project_id
  service  = each.value
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
