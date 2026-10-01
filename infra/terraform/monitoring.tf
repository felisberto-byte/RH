# Métricas a partir dos logs do portal. A aplicação registra cada evento de
# auditoria como "auditoria <ACAO> ..." em JSON (jsonPayload.message) e os jobs
# registram falhas com severity=ERROR.
locals {
  app_log = "resource.type=(\"cloud_run_revision\" OR \"cloud_run_job\")"
  log_metrics = {
    integridade-falhou = "${local.app_log} AND jsonPayload.message:\"auditoria INTEGRIDADE_FALHOU\""
    login-falhou       = "${local.app_log} AND jsonPayload.message:\"auditoria LOGIN_FALHOU\""
    cadeia-falhou      = "${local.app_log} AND jsonPayload.message:\"CADEIA DE AUDITORIA COM FALHA\""
    certificado-vence  = "${local.app_log} AND jsonPayload.message:\"CERTIFICADO e-CNPJ vence\""
    job-falhou         = "resource.type=\"cloud_run_job\" AND resource.labels.job_name=~\"^${var.name}-\" AND severity>=ERROR"
    erro-inesperado    = "resource.type=\"cloud_run_revision\" AND jsonPayload.message:\"erro inesperado ref=\""
  }
  # Métricas que geram alerta imediato (qualquer ocorrência).
  alert_metrics = ["integridade-falhou", "cadeia-falhou", "certificado-vence", "job-falhou"]
}

resource "google_logging_metric" "portal" {
  for_each = local.log_metrics
  name     = "${var.name}-${each.key}"
  filter   = each.value
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_notification_channel" "email" {
  for_each     = toset(var.alert_emails)
  display_name = "Portal do Colaborador - ${each.value}"
  type         = "email"
  labels = {
    email_address = each.value
  }
}

resource "google_monitoring_alert_policy" "log_metric" {
  for_each              = length(var.alert_emails) > 0 ? toset(local.alert_metrics) : toset([])
  display_name          = "Portal: ${each.value}"
  combiner              = "OR"
  notification_channels = [for c in google_monitoring_notification_channel.email : c.id]
  conditions {
    display_name = each.value
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.portal[each.value].name}\" AND resource.type=one_of(\"cloud_run_revision\", \"cloud_run_job\")"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  documentation {
    content   = "Ver docs/operacao.md (seção de alertas) para o procedimento."
    mime_type = "text/markdown"
  }
}

# Prontidão pública (/readyz): banco acessível e certificado de selo válido.
resource "google_monitoring_uptime_check_config" "readyz" {
  display_name = "${var.name}-readyz"
  timeout      = "10s"
  period       = "300s"
  http_check {
    path         = "/readyz"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.domain
    }
  }
}

resource "google_monitoring_alert_policy" "readyz" {
  count                 = length(var.alert_emails) > 0 ? 1 : 0
  display_name          = "Portal: indisponível (readyz)"
  combiner              = "OR"
  notification_channels = [for c in google_monitoring_notification_channel.email : c.id]
  conditions {
    display_name = "readyz falhando"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.label.check_id=\"${google_monitoring_uptime_check_config.readyz.uptime_check_id}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "600s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.label.host"]
      }
    }
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
  filter                 = "${local.app_log} AND jsonPayload.message:\"auditoria \""
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
