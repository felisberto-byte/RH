variable "project_id" {
  description = "ID do projeto GCP."
  type        = string
}

variable "region" {
  description = "Região (LGPD/latência): São Paulo."
  type        = string
  default     = "southamerica-east1"
}

variable "name" {
  description = "Prefixo dos recursos."
  type        = string
  default     = "portal"
}

variable "image" {
  description = "Imagem do portal no Artifact Registry (ex.: southamerica-east1-docker.pkg.dev/PROJ/portal/portal:1.0.0)."
  type        = string
}

variable "domain" {
  description = "Domínio público do portal (ex.: portal.empresa.com.br). Requer registro A apontando para o IP de saída."
  type        = string
}

variable "company_name" {
  type = string
}

variable "company_cnpj" {
  type = string
}

# ------------------------------------------------------------------ rede / VPN
variable "subnet_cidr" {
  description = "Sub-rede de saída do Cloud Run (Direct VPC egress) — /26 ou maior."
  type        = string
  default     = "10.20.0.0/26"
}

variable "onprem_cidrs" {
  description = "Faixas da rede local da empresa alcançadas pela VPN."
  type        = list(string)
}

variable "dc_ips" {
  description = "IPs dos controladores de domínio (LDAPS 636)."
  type        = list(string)
}

variable "vpn_peer_ip" {
  description = "IP público do firewall/roteador da empresa (par IPsec). Vazio = não cria VPN."
  type        = string
  default     = ""
}

variable "vpn_shared_secret" {
  description = "Chave pré-compartilhada IPsec (use TF_VAR_vpn_shared_secret; não versione)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "ad_dns_domain" {
  description = "Domínio DNS do AD (ex.: empresa.local.) para zona privada no Cloud DNS. Vazio = não cria."
  type        = string
  default     = ""
}

variable "dc_dns_records" {
  description = "Registros A dos DCs na zona privada: { \"dc01\" = \"10.0.0.10\" }."
  type        = map(string)
  default     = {}
}

# ------------------------------------------------------------------ portal / AD
variable "ldap_url" {
  type    = string
  default = "ldaps://dc01.empresa.local:636"
}

variable "ldap_bind_dn" {
  type = string
}

variable "ldap_base_dn" {
  type = string
}

variable "ldap_group_users_dn" {
  type    = string
  default = ""
}

variable "ldap_group_admin_dn" {
  type = string
}

variable "ldap_employee_id_attr" {
  type    = string
  default = "employeeNumber"
}

variable "accept_mfa" {
  description = "Segundo fator no aceite: none | totp (recomendado)."
  type        = string
  default     = "totp"
}

variable "tsa_url" {
  description = "URL RFC 3161 da ACT (ICP-Brasil recomendada). Vazio = sem carimbo do tempo."
  type        = string
  default     = ""
}

variable "tsa_username" {
  type    = string
  default = ""
}

variable "signature_policy_oid" {
  description = "OID da política ICP-Brasil (DOC-ICP-15.03). Vazio = sem política."
  type        = string
  default     = ""
}

variable "signature_policy_hash_b64" {
  type    = string
  default = ""
}

variable "signature_policy_uri" {
  type    = string
  default = ""
}

# ------------------------------------------------------------------ dados
variable "db_tier" {
  description = "Tier do Cloud SQL (produção pequena: db-custom-1-3840; teste: db-f1-micro)."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_high_availability" {
  description = "REGIONAL (HA) ou ZONAL."
  type        = bool
  default     = false
}

variable "documents_retention_days" {
  description = "Retenção mínima (WORM) dos PDFs. 3650 = 10 anos. Prazos maiores por classe são controlados pela aplicação."
  type        = number
  default     = 3650
}

variable "lock_retention_policy" {
  description = "Bucket Lock: IRREVERSÍVEL. Ative só após aprovação jurídica da temporalidade."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------ borda
variable "allowed_country_codes" {
  description = "Países permitidos no Cloud Armor (vazio = todos)."
  type        = list(string)
  default     = ["BR"]
}

variable "login_rate_limit_per_minute" {
  description = "Requisições/minuto por IP em /login antes de bloquear."
  type        = number
  default     = 20
}

variable "waf_preview" {
  description = "Regras WAF apenas registram (true) ou bloqueiam (false)."
  type        = bool
  default     = true
}

variable "audit_log_retention_days" {
  description = "Retenção do bucket de logs de auditoria (cópia imutável dos eventos do portal)."
  type        = number
  default     = 3650
}

variable "lock_audit_log_bucket" {
  description = "Trava a retenção do bucket de logs (IRREVERSÍVEL)."
  type        = bool
  default     = false
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 4
}

variable "deletion_protection" {
  type    = bool
  default = true
}
