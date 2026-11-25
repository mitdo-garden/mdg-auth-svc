package awskms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/mitdo-garden/mdg-auth-svc/internal/config"
)

// LoadAppSecrets reads OAuth, session_secret, and optional MySQL fields from AWS Secrets Manager.
// Skips when SecretsID is empty (caller may rely on env overrides only).
func LoadAppSecrets(ctx context.Context, cfg *config.Config) error {
	id := cfg.KMS.SecretsID
	if id == "" {
		return nil
	}
	awsCfg, err := loadAWSConfig(ctx, cfg.KMS)
	if err != nil {
		return fmt.Errorf("secretsmanager: %w", err)
	}
	cli := secretsmanager.NewFromConfig(awsCfg)
	out, err := cli.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return fmt.Errorf("secretsmanager get %q: %w", id, err)
	}
	raw := ""
	if out.SecretString != nil {
		raw = *out.SecretString
	}
	if raw == "" {
		return fmt.Errorf("secretsmanager %q: empty secret string", id)
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return fmt.Errorf("secretsmanager %q: expect JSON object: %w", id, err)
	}
	cfg.ApplyAppSecrets(data)
	return nil
}
