terraform {
  required_version = ">= 1.5.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

provider "vault" {
  address = var.vault_address
  token   = var.vault_token
}

resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Mitdo JWT Transit (${var.environment})"
}

resource "vault_mount" "kv" {
  path        = "secret"
  type        = "kv"
  options     = { version = "2" }
  description = "Mitdo app secrets (${var.environment})"
}

resource "vault_transit_secret_backend_key" "jwt_access" {
  backend = vault_mount.transit.path
  name    = var.transit_key_name
  type    = "ecdsa-p256"

  # Private material stays in Vault; apps only sign + read public.
  exportable             = false
  allow_plaintext_backup = false
  deletion_allowed       = var.allow_key_deletion
}

resource "vault_policy" "mdg_auth_jwt" {
  name   = "mdg-auth-jwt"
  policy = <<-EOT
    path "transit/sign/${var.transit_key_name}" {
      capabilities = ["update"]
    }
    path "transit/sign/${var.transit_key_name}/*" {
      capabilities = ["update"]
    }
    path "transit/keys/${var.transit_key_name}" {
      capabilities = ["read"]
    }
    path "secret/data/mdg-auth/*" {
      capabilities = ["read"]
    }
    path "secret/metadata/mdg-auth/*" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "mdg_auth_jwt_rotator" {
  name   = "mdg-auth-jwt-rotator"
  policy = <<-EOT
    path "transit/keys/${var.transit_key_name}/rotate" {
      capabilities = ["update"]
    }
    path "transit/keys/${var.transit_key_name}" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

resource "vault_approle_auth_backend_role" "mdg_auth_svc" {
  backend        = vault_auth_backend.approle.path
  role_name      = "mdg-auth-svc"
  token_policies = [vault_policy.mdg_auth_jwt.name]
  token_ttl      = 3600
  token_max_ttl  = 14400
}

resource "vault_approle_auth_backend_role" "mdg_auth_rotator" {
  backend        = vault_auth_backend.approle.path
  role_name      = "mdg-auth-jwt-rotator"
  token_policies = [vault_policy.mdg_auth_jwt_rotator.name]
  token_ttl      = 900
  token_max_ttl  = 1800
}

data "vault_approle_auth_backend_role_id" "mdg_auth_svc" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.mdg_auth_svc.role_name
}

data "vault_approle_auth_backend_role_id" "mdg_auth_rotator" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.mdg_auth_rotator.role_name
}

resource "vault_approle_auth_backend_role_secret_id" "mdg_auth_svc" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.mdg_auth_svc.role_name
}

resource "vault_approle_auth_backend_role_secret_id" "mdg_auth_rotator" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.mdg_auth_rotator.role_name
}
