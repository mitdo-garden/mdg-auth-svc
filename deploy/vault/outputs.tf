output "transit_key" {
  value = vault_transit_secret_backend_key.jwt_access.name
}

output "auth_role_id" {
  value = data.vault_approle_auth_backend_role_id.mdg_auth_svc.role_id
}

output "auth_secret_id" {
  value     = vault_approle_auth_backend_role_secret_id.mdg_auth_svc.secret_id
  sensitive = true
}

output "rotator_role_id" {
  value = data.vault_approle_auth_backend_role_id.mdg_auth_rotator.role_id
}

output "rotator_secret_id" {
  value     = vault_approle_auth_backend_role_secret_id.mdg_auth_rotator.secret_id
  sensitive = true
}

output "env_hint" {
  value = <<-EOT
    Inject into mdg-auth-svc (${var.environment}):
      VAULT_ADDR=${var.vault_address}
      VAULT_ROLE_ID=<auth_role_id>
      VAULT_SECRET_ID=<auth_secret_id>
      VAULT_TRANSIT_KEY=${var.transit_key_name}
  EOT
}
