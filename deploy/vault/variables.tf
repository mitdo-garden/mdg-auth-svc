variable "vault_address" {
  type        = string
  description = "Vault API address for this environment"
  default     = "http://127.0.0.1:8200"
}

variable "vault_token" {
  type        = string
  description = "Bootstrap token for Terraform (never the app token)"
  sensitive   = true
}

variable "environment" {
  type        = string
  description = "dev | staging | prd — separate state/workspace per env"
}

variable "transit_key_name" {
  type        = string
  description = "Transit key name (same across envs; material is per-Vault)"
  default     = "jwt-access"
}

variable "allow_key_deletion" {
  type        = bool
  description = "Allow deleting the Transit key (dev only)"
  default     = false
}
