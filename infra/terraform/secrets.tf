# Segredos gerados pelo Terraform (ficam no estado: use backend GCS com acesso
# restrito) e "contêineres" de segredos cujo VALOR é carregado fora do Terraform
# (gcloud secrets versions add ...), para que o e-CNPJ e senhas do AD nunca
# passem pelo estado. Ver docs/implantacao-gcp.md.
locals {
  replication_location = var.region

  external_secrets = merge({
    "ldap-bind-password" = "Senha da conta de serviço somente leitura do AD"
    "ad-ca-pem"          = "Certificado (PEM) da AC que emitiu o certificado LDAPS dos DCs"
    "ecnpj-pfx"          = "e-CNPJ A1 (PKCS#12 binário)"
    "ecnpj-pfx-password" = "Senha do e-CNPJ A1"
    "tsa-password"       = "Senha da ACT (carimbo do tempo), se houver"
    "icp-raizes-pem"     = "Certificados raiz/intermediários ICP-Brasil (PEM concatenado, fonte: ITI)"
    }, var.ecnpj_chain_separate ? {
    "ecnpj-cadeia-pem" = "Cadeia (PEM) da AC emissora do e-CNPJ, quando não incluída no PFX"
  } : {})

  # Segredos gerados: os da aplicação e os exclusivos do job de migração.
  app_secrets     = ["portal-secret-key", "database-url"]
  migrate_secrets = ["database-url-owner", "db-app-password"]
}

resource "random_password" "secret_key" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "generated" {
  for_each  = toset(concat(local.app_secrets, local.migrate_secrets))
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
    "portal_app",
    random_password.db_app.result,
    google_sql_database_instance.portal.private_ip_address,
    google_sql_database.portal.name,
  )
}

resource "google_secret_manager_secret_version" "database_url_owner" {
  secret = google_secret_manager_secret.generated["database-url-owner"].id
  secret_data = format(
    "postgresql+psycopg://%s:%s@%s/%s?sslmode=require",
    google_sql_user.owner.name,
    random_password.db_owner.result,
    google_sql_database_instance.portal.private_ip_address,
    google_sql_database.portal.name,
  )
}

resource "google_secret_manager_secret_version" "db_app_password" {
  secret      = google_secret_manager_secret.generated["db-app-password"].id
  secret_data = random_password.db_app.result
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
