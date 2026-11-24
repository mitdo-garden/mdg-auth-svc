package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestMergeEnvAndProfilesChained(t *testing.T) {
	dir := t.TempDir()
	configs := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configs, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(configs, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("config.yaml", "app:\n  name: base\n  profiles: []\nflag:\n  value: base\n")
	mustWrite("config.dev.yaml", "app:\n  env: dev\n  profiles: [extra]\nflag:\n  value: dev\n")
	mustWrite("config.extra.yaml", "flag:\n  value: extra\nextra:\n  on: true\n")

	v := viper.New()
	v.AddConfigPath(configs)
	v.SetConfigType("yaml")
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if err := mergeEnvAndProfiles(v, "dev"); err != nil {
		t.Fatal(err)
	}
	if got := v.GetString("flag.value"); got != "extra" {
		t.Fatalf("flag.value=%s want extra", got)
	}
	if !v.GetBool("extra.on") {
		t.Fatal("expected extra.on from chained profile")
	}
}

func TestAPP_PROFILESEnv(t *testing.T) {
	dir := t.TempDir()
	configs := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configs, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(configs, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("config.yaml", "x: 1\n")
	mustWrite("config.prd.yaml", "app:\n  env: prd\n")
	mustWrite("config.aws.yaml", "kms:\n  region: ap-southeast-1\n")

	t.Setenv("APP_PROFILES", "aws")

	v := viper.New()
	v.AddConfigPath(configs)
	v.SetConfigType("yaml")
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if err := mergeEnvAndProfiles(v, "prd"); err != nil {
		t.Fatal(err)
	}
	if got := v.GetString("kms.region"); got != "ap-southeast-1" {
		t.Fatalf("kms.region=%s", got)
	}
}
