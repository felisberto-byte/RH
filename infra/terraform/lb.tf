# HTTPS Load Balancer global (externo) -> NEG serverless -> Cloud Run, com
# certificado gerenciado e Cloud Armor (limite em /login e restrição por país).
resource "google_compute_global_address" "lb" {
  name       = "${var.name}-lb-ip"
  depends_on = [google_project_service.apis]
}

resource "google_compute_region_network_endpoint_group" "run" {
  name                  = "${var.name}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = google_cloud_run_v2_service.portal.name
  }
}

resource "google_compute_security_policy" "portal" {
  name        = "${var.name}-armor"
  description = "Portal do Colaborador"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      expr {
        expression = "request.path.startsWith('/login') || request.path.startsWith('/verificar') || (request.method == 'POST' && request.path.matches('/(termo|documentos/.*/(aceite|recusa|docuseal))'))"
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.login_rate_limit_per_minute
        interval_sec = 60
      }
    }
    description = "Limita tentativas de login, verificação e confirmações por IP"
  }

  # Regras OWASP pré-configuradas. Comece em modo de avaliação (preview) e
  # observe os logs antes de bloquear (uploads de PDF podem gerar falsos positivos).
  dynamic "rule" {
    for_each = {
      3000 = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})"
      3001 = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"
      3002 = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})"
    }
    content {
      action   = "deny(403)"
      priority = rule.key
      preview  = var.waf_preview
      match {
        expr {
          expression = rule.value
        }
      }
      description = "WAF OWASP"
    }
  }

  dynamic "rule" {
    for_each = length(var.allowed_country_codes) == 0 ? [] : [1]
    content {
      action   = "deny(403)"
      priority = 2000
      match {
        expr {
          expression = format(
            "!(%s)",
            join(" || ", [for c in var.allowed_country_codes : "origin.region_code == '${c}'"]),
          )
        }
      }
      description = "Bloqueia acessos fora dos países permitidos"
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Padrão"
  }
}

resource "google_compute_backend_service" "portal" {
  name                  = "${var.name}-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.portal.id
  backend {
    group = google_compute_region_network_endpoint_group.run.id
  }
  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "portal" {
  name            = "${var.name}-urlmap"
  default_service = google_compute_backend_service.portal.id
}

resource "google_compute_managed_ssl_certificate" "portal" {
  name = "${var.name}-cert"
  managed {
    domains = [var.domain]
  }
}

resource "google_compute_ssl_policy" "modern" {
  name            = "${var.name}-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "portal" {
  name             = "${var.name}-https"
  url_map          = google_compute_url_map.portal.id
  ssl_certificates = [google_compute_managed_ssl_certificate.portal.id]
  ssl_policy       = google_compute_ssl_policy.modern.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "${var.name}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "443"
  target                = google_compute_target_https_proxy.portal.id
}

# HTTP -> HTTPS
resource "google_compute_url_map" "redirect" {
  name = "${var.name}-redirect"
  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "${var.name}-http"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "${var.name}-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "80"
  target                = google_compute_target_http_proxy.redirect.id
}
