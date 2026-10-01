# Segredos gerados pelo Terraform (ficam no estado: use backend GCS com acesso
# restrito) e "contêineres" de segredos cujo VALOR é carregado fora do Terraform
# (gcloud secrets versions add ...), para que o e-CNPJ e senhas do AD nunca
# passem pelo estado. Ver docs/implantacao-gcp.md.
locals {
  replication_location = var.region

  external_secrets = {
    "ldap-bind-password" = "Senha da conta de serviço somente leitura do AD"
    "ad-ca-pem"          = "Certificado (PEM) da AC que emitiu o certificado LDAPS dos DCs"
    "ecnpj-pfx"          = "e-CNPJ A1 (PKCS#12 binário)"
    "ecnpj-pfx-password" = "Senha do e-CNPJ A1"
    "tsa-password"       = "Senha da ACT (carimbo do tempo), se houver"
  }
}

resource "random_password" "secret_key" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "generated" {
  for_each  = toset(["portal-secret-key", "database-url"])
  secret_id = "${var.name}-${each.value}"
  replication {
    user_managed {
      replicas {
        location = local.replication_location
      }
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "secret_key" {
  secret      = google_secret_manager_secret.generated["portal-secret-key"].id
  secret_data = random_password.secret_key.result
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.generated["database-url"].id
  secret_data = format(
    "postgresql+psycopg://%s:%s@%s/%s?sslmode=require",
    google_sql_user.portal.name,
    random_password.db.result,
    google_sql_database_instance.portal.private_ip_address,
    google_sql_database.portal.name,
  )
}

resource "google_secret_manager_secret" "external" {
  for_each  = local.external_secrets
  secret_id = "${var.name}-${each.key}"
  labels    = { carregado_por = "operador" }
  annotations = {
    descricao = each.value
  }
  replication {
    user_managed {
      replicas {
        location = local.replication_location
      }
    }
  }
  depends_on = [google_project_service.apis]
}
