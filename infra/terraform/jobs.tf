# Jobs de operação (mesma imagem): ancoragem e verificação da auditoria,
# alerta de validade do e-CNPJ e expurgo de dados operacionais. A migração do
# banco é um job à parte, com conta de serviço própria (credencial do dono).
locals {
  jobs = {
    anchor-audit = { args = ["portal", "anchor-audit"], schedule = "15 2 * * *" }
    verify-audit = { args = ["portal", "verify-audit"], schedule = "45 2 * * *" }
    cert-info    = { args = ["portal", "cert-info", "--alerta-dias", "45"], schedule = "50 7 * * 1" }
    purge        = { args = ["portal", "purge", "--dias", "180"], schedule = "30 3 * * 0" }
  }
}

# Migração: cria/atualiza o papel portal_app (privilégios mínimos) e aplica o
# Alembic com o dono do esquema. Execute após cada nova imagem:
#   gcloud run jobs execute portal-migrate --region southamerica-east1 --wait
resource "google_cloud_run_v2_job" "migrate" {
  name                = "${var.name}-migrate"
  location            = var.region
  deletion_protection = var.deletion_protection

  template {
    template {
      service_account = google_service_account.migrate.email
      max_retries     = 0
      timeout         = "900s"

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.run.id
        }
      }

      containers {
        image   = var.image
        command = ["sh", "-c"]
        args    = ["portal db-app-role --papel portal_app && alembic -x app_role=portal_app upgrade head"]

        env {
          name  = "PORTAL_ENV"
          value = "prod"
        }
        env {
          name  = "PORTAL_LOG_FORMAT"
          value = "json"
        }
        env {
          name = "PORTAL_DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.generated["database-url-owner"].secret_id
              version = "latest"
            }
          }
        }
        env {
          name = "PORTAL_DB_APP_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.generated["db-app-password"].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.migrate,
    google_secret_manager_secret_version.database_url_owner,
    google_secret_manager_secret_version.db_app_password,
  ]
}

resource "google_cloud_run_v2_job" "ops" {
  for_each            = local.jobs
  name                = "${var.name}-${each.key}"
  location            = var.region
  deletion_protection = var.deletion_protection

  template {
    template {
      service_account = google_service_account.portal.email
      max_retries     = 1
      timeout         = "1800s"

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.run.id
        }
      }

      dynamic "volumes" {
        for_each = local.secret_files
        content {
          name = volumes.key
          secret {
            secret = volumes.value.secret
            items {
              version = "latest"
              path    = volumes.value.path
            }
          }
        }
      }

      containers {
        image   = var.image
        command = [each.value.args[0]]
        args    = slice(each.value.args, 1, length(each.value.args))

        dynamic "env" {
          for_each = local.plain_env
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = local.secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }

        dynamic "volume_mounts" {
          for_each = local.secret_files
          content {
            name       = volume_mounts.key
            mount_path = "/secrets/${volume_mounts.key}"
          }
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.generated,
    google_secret_manager_secret_iam_member.external,
  ]
}

resource "google_cloud_run_v2_job_iam_member" "scheduler" {
  for_each = { for k, v in local.jobs : k => v if v.schedule != null }
  name     = google_cloud_run_v2_job.ops[each.key].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "ops" {
  for_each  = { for k, v in local.jobs : k => v if v.schedule != null }
  name      = "${var.name}-${each.key}"
  region    = var.region
  schedule  = each.value.schedule
  time_zone = "America/Sao_Paulo"

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/${google_cloud_run_v2_job.ops[each.key].id}:run"
    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.apis]
}
