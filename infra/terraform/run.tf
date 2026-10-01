locals {
  base_url = "https://${var.domain}"

  # Variáveis comuns ao serviço e aos jobs.
  plain_env = merge(
    {
      PORTAL_ENV                       = "prod"
      PORTAL_BASE_URL                  = local.base_url
      PORTAL_COMPANY_NAME              = var.company_name
      PORTAL_COMPANY_CNPJ              = var.company_cnpj
      PORTAL_STORAGE_BACKEND           = "gcs"
      PORTAL_STORAGE_GCS_BUCKET        = google_storage_bucket.documents.name
      PORTAL_AUTH_PROVIDER             = "ldap"
      PORTAL_LDAP_URL                  = var.ldap_url
      PORTAL_LDAP_CA_CERT_FILE         = "/secrets/ad-ca/ad-ca.pem"
      PORTAL_LDAP_BIND_DN              = var.ldap_bind_dn
      PORTAL_LDAP_BASE_DN              = var.ldap_base_dn
      PORTAL_LDAP_GROUP_USERS_DN       = var.ldap_group_users_dn
      PORTAL_LDAP_GROUP_ADMIN_DN       = var.ldap_group_admin_dn
      PORTAL_LDAP_EMPLOYEE_ID_ATTR     = var.ldap_employee_id_attr
      PORTAL_SIGNING_PFX_FILE          = "/secrets/ecnpj/ecnpj.pfx"
      PORTAL_ACCEPT_REAUTH             = "password"
      PORTAL_ACCEPT_MFA                = var.accept_mfa
      PORTAL_TSA_URL                   = var.tsa_url
      PORTAL_TSA_USERNAME              = var.tsa_username
      PORTAL_SIGNATURE_POLICY_OID      = var.signature_policy_oid
      PORTAL_SIGNATURE_POLICY_HASH_B64 = var.signature_policy_hash_b64
      PORTAL_SIGNATURE_POLICY_URI      = var.signature_policy_uri
      # Cliente -> Load Balancer externo -> Cloud Run: X-Forwarded-For chega como
      # "<cliente>, <IP do LB>"; o IP real é o 2º da direita.
      PORTAL_TRUSTED_PROXY_HOPS = "2"
    },
  )

  secret_env = merge(
    {
      PORTAL_SECRET_KEY           = google_secret_manager_secret.generated["portal-secret-key"].secret_id
      PORTAL_DATABASE_URL         = google_secret_manager_secret.generated["database-url"].secret_id
      PORTAL_LDAP_BIND_PASSWORD   = google_secret_manager_secret.external["ldap-bind-password"].secret_id
      PORTAL_SIGNING_PFX_PASSWORD = google_secret_manager_secret.external["ecnpj-pfx-password"].secret_id
    },
    var.tsa_username == "" ? {} : {
      PORTAL_TSA_PASSWORD = google_secret_manager_secret.external["tsa-password"].secret_id
    },
  )

  secret_files = {
    ecnpj = { secret = google_secret_manager_secret.external["ecnpj-pfx"].secret_id, path = "ecnpj.pfx" }
    ad-ca = { secret = google_secret_manager_secret.external["ad-ca-pem"].secret_id, path = "ad-ca.pem" }
  }
}

resource "google_cloud_run_v2_service" "portal" {
  name                = "${var.name}-web"
  location            = var.region
  deletion_protection = var.deletion_protection
  # Só aceita tráfego vindo do Load Balancer (Cloud Armor na frente) e desativa
  # a URL *.run.app, que permitiria contornar o Cloud Armor.
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  default_uri_disabled = true

  template {
    service_account = google_service_account.portal.email
    timeout         = "300s"

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.run.id
        tags       = ["ldap-client"]
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
      image = var.image
      ports {
        container_port = 8080
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

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

      startup_probe {
        http_get {
          path = "/healthz"
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 6
      }
      liveness_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds = 30
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.generated,
    google_secret_manager_secret_iam_member.external,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.secret_key,
  ]
}

# Acesso público ao serviço (a autenticação é feita pelo próprio portal); o
# ingress acima restringe a origem ao Load Balancer.
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.portal.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
