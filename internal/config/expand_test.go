package config

import "testing"

func TestExpandStringDefault(t *testing.T) {
	got := ExpandString("${DOES_NOT_EXIST_XYZ:mdg_auth}")
	if got != "mdg_auth" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandStringEnvWins(t *testing.T) {
	t.Setenv("DATABASE_NAME", "from_env")
	got := ExpandString("${DATABASE_NAME:mdg_auth}")
	if got != "from_env" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandStringURLDefault(t *testing.T) {
	got := ExpandString("${VAULT_ADDR_UNSET:http://127.0.0.1:8200}")
	if got != "http://127.0.0.1:8200" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandStringNested(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-southeast-1")
	got := ExpandString("${KMS_REGION_UNSET:${AWS_REGION:us-east-1}}")
	if got != "ap-southeast-1" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandStringEmptyDefault(t *testing.T) {
	got := ExpandString("${UNSET_TOKEN:}")
	if got != "" {
		t.Fatalf("got %q", got)
	}
}
