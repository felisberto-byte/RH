# Dois usuários no banco:
# - portal_owner: dono do esquema; usado SÓ pelo job de migração.
# - portal_app: usado pela aplicação; criado via SQL pelo job de migração
#   (`portal db-app-role`), pois usuários criados pela API do Cloud SQL recebem
#   o papel cloudsqlsuperuser. Sem ser dono das tabelas, o app não consegue
#   remover os gatilhos que tornam auditoria/aceites somente-inclusão.
resource "random_password" "db_owner" {
  length  = 32
  special = false
}

resource "random_password" "db_app" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "portal" {
  name                = "${var.name}-pg"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

  settings {
    tier                        = var.db_tier
    edition                     = "ENTERPRISE" # PG16+ assume ENTERPRISE_PLUS se omitido
    deletion_protection_enabled = var.deletion_protection
    availability_type           = var.db_high_availability ? "REGIONAL" : "ZONAL"
    disk_autoresize             = true
    disk_type                   = "PD_SSD"

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "05:00"
      transaction_log_retention_days = 7
      location                       = var.region # backups no Brasil
      backup_retention_settings {
        retained_backups = 30
      }
    }

    maintenance_window {
      day  = 7
      hour = 6
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    insights_config {
      query_insights_enabled = true
    }
  }

  depends_on = [google_service_networking_connection.sql]
}

resource "google_sql_database" "portal" {
  name     = "portal"
  instance = google_sql_database_instance.portal.name
}

resource "google_sql_user" "owner" {
  name     = "portal_owner"
  instance = google_sql_database_instance.portal.name
  password = random_password.db_owner.result
}
